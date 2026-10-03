"""Agent definitions for the ARVO adversarial solver pipeline.

Agents:
  - Mutator:  Generates PoC variants via bash tool (exploratory or targeted).
  - Analyzer: Discovers violated safety properties from crash differentials (NEW).
  - Patcher:  Analyses crash paths AND edits source code to fix the bug,
              guided by the Analyzer's property report.
  - Selector: Picks the most robust patch candidate after all rounds.
"""

from __future__ import annotations

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient

from arvo.benchmark import POC_PATH
from arvo.config import (
    ANALYZER_MAX_TOOL_ITERS,
    API_KEY,
    BASE_URL,
    MODEL_NAME,
    MAX_TOKENS,
    REQUEST_MAX_RETRIES,
    REQUEST_TIMEOUT,
    MUTATOR_MAX_TOOL_ITERS,
    PATCH_MODE,
    PATCHER_MAX_TOOL_ITERS,
    REASONING_EFFORT,
)

#: PATCH_MODE metapro and combined build nothing before a patch reaches its PoC
#: validation: probes go into a prebuilt binary (run_probed), and the Patcher has no
#: build-and-run self check.
_NO_BUILD_BEFORE_VALIDATION = PATCH_MODE in ("metapro", "combined")
from arvo.tools import (
    _EditState,
    make_bash_tool,
    make_check_vul_tool,
    make_insert_probe_tool,
    make_mutate_poc_tool,
    make_revert_all_edits_tool,
    make_revert_last_edit_tool,
    make_run_probed_tool,
    make_run_variant_tool,
    make_search_tool,
    make_str_replace_tool,
    make_submit_tool,
    make_view_tool,
)

# ---------------------------------------------------------------------------
# Model client
# ---------------------------------------------------------------------------


def create_model_client(temperature: float | None = None) -> OpenAIChatCompletionClient:
    """Create a shared OpenAI-compatible model client.

    Args:
        temperature: Optional sampling temperature override.
    """
    kwargs: dict = dict(
        model=MODEL_NAME,
        base_url=BASE_URL,
        api_key=API_KEY,
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": "unknown",
            "structured_output": True,
        },
        timeout=REQUEST_TIMEOUT,
        max_retries=REQUEST_MAX_RETRIES,
    )
    if temperature is not None:
        kwargs["temperature"] = temperature
    if MAX_TOKENS:
        kwargs["max_tokens"] = MAX_TOKENS
    if REASONING_EFFORT:
        # OpenAI's GPT-5 models reject function tools on /v1/chat/completions
        # unless this is "none", and every agent here uses tools.  Servers that
        # do not know the parameter need SECBENCH_REASONING_EFFORT set empty.
        kwargs["reasoning_effort"] = REASONING_EFFORT
    return OpenAIChatCompletionClient(**kwargs)


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

MUTATOR_SYSTEM_MESSAGE = """\
You are a vulnerability exploitation and PoC mutation expert working inside \
a Docker container.

## Environment
- OS: Ubuntu 20.04 with Python 3.11, grep/find/ls, git, and sometimes rg
- Original PoC file: {poc_path}
- Repro command: {repro_cmd}
- PoC type: {poc_type}

## Goal
Create {num_variants} PoC variant files to enable **differential analysis** \
of the vulnerability. The downstream Analyzer compares crashing vs \
non-crashing inputs to identify the exact boundary condition (root cause), \
so you MUST produce BOTH:
- At least 1 variant that **crashes** with the SAME sanitizer error type \
  as the original PoC (e.g. if the original is heap-buffer-overflow, the \
  variant must also trigger heap-buffer-overflow)
- At least 1 variant that does **NOT crash** (a near-miss that stays just \
  below the trigger threshold — e.g. smaller input, valid boundary values, \
  correct field lengths)

## Instructions

### Preferred atomic variant tools
Use `mutate_poc` to write each explicit variant and `run_variant` to classify it.
The tool does not invent mutations; YOU choose the concrete content, offsets,
field values, and boundary values.

For text-based PoCs:
```
mutate_poc(path="{poc_path}", filename="variant_1{ext}", content="<full content>", encoding="text")
```
Then test it:
```
run_variant("variant_1")
```

For binary PoCs, prefer structured byte edits when changing a few fields:
```
mutate_poc(path="{poc_path}", filename="variant_1", edits_json='[{{"op":"set_byte","offset":12,"value":1}}]')
```
For larger binary rewrites, pass complete hex/base64 content to `mutate_poc`.
You may still use `bash` and Python for complex format-aware mutations.

### For script PoC files (poc_type = script)
Create each variant with `mutate_poc(..., encoding="text")` and test it with
`run_variant`.

## Workflow
1. First, examine the original PoC and sanitizer output to understand the vulnerability
2. Identify the specific sanitizer error type (e.g. heap-buffer-overflow, \
   use-after-free, SEGV, etc.) — this is the target error type
3. Create variant files one by one
4. After creating each variant, call `run_variant` to check the result
5. Record whether each variant crashes (with the SAME error type) or not
6. Ensure you have BOTH crashing and non-crashing variants before finishing
7. Aim for diversity: different input sizes, field values, nesting depths, \
   boundary values

## Crash Judgment
A variant is considered a **crash** ONLY if it triggers the SAME sanitizer \
error type as the original PoC. If a variant triggers a DIFFERENT sanitizer \
error, it does NOT count as a crash for this vulnerability.

## Rules
- Make semantically meaningful changes, NOT random noise
- Keep variants minimal and focused
- Variant files MUST be named /tmp/variant_1, /tmp/variant_2, etc. \
  (with appropriate extension for text/script types)
- CRITICAL: After creating each variant, you MUST run the repro command. \
  You need BOTH crashing variants (same error type as original) AND \
  non-crashing variants (near-miss inputs). Do NOT discard non-crashing \
  variants — they are equally valuable for differential analysis.
- Non-crashing variants should be deliberate near-misses: inputs that are \
  similar to crashing ones but stay just within safe bounds (e.g. \
  index=size-1 vs index=size, valid length vs overflow length).
"""

MUTATOR_TARGETED_SYSTEM_MESSAGE = """\
You are a vulnerability exploitation and PoC mutation expert working inside \
a Docker container.

## Environment
- OS: Ubuntu 20.04 with Python 3.11, grep/find/ls, git, and sometimes rg
- Original PoC file: {poc_path}
- Repro command: {repro_cmd}
- PoC type: {poc_type}

## Goal
Create {num_variants} TARGETED PoC variants that probe specific aspects of \
the vulnerability that a previous patch attempt failed to fully address. \
You MUST produce BOTH crashing and non-crashing variants for differential \
analysis.

## Context
A previous patch was applied but it was insufficient. Your variants should \
specifically probe code paths that the previous patch did NOT cover, to help \
distinguish between a superficial fix and a true root-cause fix.

## Crash Judgment
A variant is considered a **crash** ONLY if it triggers the SAME sanitizer \
error type as the original PoC. A different sanitizer error does NOT count.

## Workflow
1. Review the previous patch and failure feedback
2. Identify what the patch missed
3. If unresolved safety properties are provided, design variants that \
   probe each property's boundary condition (e.g., if the property is \
   "index < size", generate variants with index=size, size-1, size+1, \
   0, -1, etc.)
4. Create variant files with `mutate_poc`; for binary PoCs, prefer explicit \
   byte edits such as `edits_json='[{{"op":"set_byte","offset":12,"value":1}}]'` \
   when changing a known field. You choose the offsets/values; the tool only \
   writes the variant. Include \
   BOTH inputs that should crash AND inputs that should NOT crash
5. Test each variant with `run_variant` and record the result
6. Ensure you have at least 1 crashing and 1 non-crashing variant

## Rules
- Variant files MUST be named /tmp/variant_1, /tmp/variant_2, etc.
- Focus on paths the previous patch did NOT cover
- Make semantically meaningful changes, not random noise
- For complex binary PoCs, you may still use `bash` and Python to construct \
  format-aware variants, then run each one with `run_variant`
- For text PoCs, prefer `mutate_poc(..., encoding="text")`
- CRITICAL: You need BOTH crashing variants (same error type as original) \
  AND non-crashing variants (near-miss inputs). Do NOT discard non-crashing \
  variants — they are essential for differential analysis.
"""

ANALYZER_SYSTEM_MESSAGE = """\
You are a vulnerability differential analysis and safety property discovery \
expert working inside a Docker container.

## Your Tools
- **bash**: Read source code (cat -n), search patterns, explore \
  directories (ls/find), and run one-off commands.
- **insert_probe**: Insert explicit probe code before/after a unique source \
  anchor. You decide which variables/expressions to print.
- **str_replace_edit**: Insert diagnostic probes into source code to \
  observe runtime values when a larger exact text edit is needed.
- **run_probed**: Build once and run selected PoC ids after probes are inserted.

## Your Task
From the crash / no-crash differential results of multiple PoC variants, \
deduce the violated safety properties that the patch must restore.

## Analysis Workflow

### a. Crash Convergence Analysis
Examine all crashing variants' sanitizer stack traces. Identify the \
**convergence point**: the deepest function/line that appears in ALL \
crashing variants' call stacks.

### b. Differential Comparison
Compare crashing vs non-crashing variants. What input characteristics \
distinguish the two groups? Identify the **boundary condition** that \
separates crash from no-crash.

### c. Code Localisation
Read the source code at and around the convergence point using \
`bash("cat -n /src/.../file.c")`. Understand the code semantics — \
what does this function assume about its inputs?

### d. Dynamic Probe Verification (IMPORTANT)
After reading the code, you should insert diagnostic probes to observe \
actual runtime values. This helps you confirm or reject hypotheses about \
the root cause. The workflow is:

1. **Decide what to observe**: Based on the crash site and your hypotheses, \
   decide which variables, array indices, sizes, pointers, or conditions \
   you need to inspect at runtime.
2. **Insert probes**: Prefer `insert_probe` to add `dprintf(2, ...)` \
   statements at strategic locations. For example:
   - Print array index vs bound: \
     `dprintf(2, "PROBE: idx=%d size=%d\\n", idx, arr->size);`
   - Print pointer value: \
     `dprintf(2, "PROBE: ptr=%p\\n", (void*)ptr);`
   - Print control flow: \
     `dprintf(2, "PROBE: reached branch X\\n");`
   Use the prefix "PROBE:" so output is easy to grep.
3. **Build and run**: Use `run_probed("original,variant_1,variant_2")` to \
   build the project and run the original PoC and/or selected variants. \
   Capture the PROBE output.
4. **Analyse probe output**: The observed values tell you the exact \
   runtime state. Use this to confirm boundary conditions and refine \
   your property derivation.
5. **You may iterate**: If the first round of probes is inconclusive, \
   insert additional probes at different locations and re-run. Use your \
   judgement on what to probe — you are the expert.

NOTE: The pipeline will automatically clean up your probe edits after \
you finish. Do NOT spend time reverting your changes.

### e. Property Derivation
Formalise each boundary condition as a **safety property** — a condition \
that SHOULD hold but is currently violated. Express it as:
- Location: file:function (or file:line)
- Condition: e.g. "index < array->length before access"
- Category: one of {bounds-check, null-check, type-check, \
  lifetime-check, integer-overflow, resource-limit, init-check}

### f. Confidence Assessment
Rate each property by the number of variants that support it AND \
whether it was confirmed by dynamic probes:
- HIGH: confirmed by probe output OR supported by ≥3 crashing variants
- MEDIUM: supported by 1-2 variants without probe confirmation
- LOW: inferred indirectly

## Output Format

Produce a structured **Property Analysis Report** in this exact markdown \
format:

```
# Property Analysis Report

## PROPERTY 1
- **Location**: <file>:<function> (line ~<N>)
- **Condition**: <what should hold>
- **Confidence**: HIGH | MEDIUM | LOW
- **Evidence**: <which variants support this, why>
- **Probe Result**: <what the dynamic probe revealed, or "N/A">
- **Category**: <category>

## PROPERTY 2
...

## Insights
<1-3 sentences summarising the root cause and how the properties relate>
```

Important: output ONLY the Property Analysis Report. Do not include any \
other text before or after it.
"""

ANALYZER_SINGLE_CRASH_SYSTEM_MESSAGE = """\
You are a vulnerability root cause analysis and safety property discovery \
expert working inside a Docker container.

## Your Tools
- **bash**: Read source code (cat -n), search patterns, explore \
  directories (ls/find), and run one-off commands.
- **insert_probe**: Insert explicit probe code before/after a unique source \
  anchor. You decide which variables/expressions to print.
- **str_replace_edit**: Insert diagnostic probes into source code to \
  observe runtime values when a larger exact text edit is needed.
- **run_probed**: Build once and run the original PoC after probes are inserted.

## Your Task
From the original PoC crash report and source code analysis, deduce the \
violated safety properties that the patch must restore.

NOTE: You do NOT have variant PoC crash reports. You must derive properties \
from the original crash alone, combined with source code reading and \
dynamic probes.

## Analysis Workflow

### a. Crash Site Analysis
Examine the sanitizer stack trace from the original PoC crash. Identify \
the **crash site**: the exact function and line where the error occurs.

### b. Code Localisation
Read the source code at and around the crash site using \
`bash("cat -n /src/.../file.c")`. Understand the code semantics — \
what does this function assume about its inputs? Trace the data flow \
backwards to find where the violated assumption originates.

### c. Dynamic Probe Verification (IMPORTANT)
Insert diagnostic probes to observe actual runtime values:

1. **Decide what to observe**: Based on the crash site and your hypotheses, \
   decide which variables, array indices, sizes, pointers, or conditions \
   you need to inspect at runtime.
2. **Insert probes**: Prefer `insert_probe` to add `dprintf(2, ...)` \
   statements at strategic locations. Use the prefix "PROBE:" so output \
   is easy to grep.
3. **Build and run**: Call `run_probed("original")` to build the project and \
   run the original PoC. Capture the PROBE output.
4. **Analyse probe output**: The observed values tell you the exact \
   runtime state. Use this to confirm boundary conditions.
5. **You may iterate**: If the first round of probes is inconclusive, \
   insert additional probes at different locations and re-run.

NOTE: The pipeline will automatically clean up your probe edits after \
you finish. Do NOT spend time reverting your changes.

### d. Property Derivation
Formalise each boundary condition as a **safety property**:
- Location: file:function (or file:line)
- Condition: e.g. "index < array->length before access"
- Category: one of {bounds-check, null-check, type-check, \
  lifetime-check, integer-overflow, resource-limit, init-check}

### e. Confidence Assessment
Rate each property:
- HIGH: confirmed by probe output
- MEDIUM: supported by code analysis without probe confirmation
- LOW: inferred indirectly

## Output Format

Produce a structured **Property Analysis Report** in this exact markdown \
format:

```
# Property Analysis Report

## PROPERTY 1
- **Location**: <file>:<function> (line ~<N>)
- **Condition**: <what should hold>
- **Confidence**: HIGH | MEDIUM | LOW
- **Evidence**: <code analysis and probe results supporting this>
- **Probe Result**: <what the dynamic probe revealed, or "N/A">
- **Category**: <category>

## PROPERTY 2
...

## Insights
<1-3 sentences summarising the root cause and how the properties relate>
```

Important: output ONLY the Property Analysis Report. Do not include any \
other text before or after it.
"""

PATCHER_SYSTEM_MESSAGE = """\
You are a C/C++ vulnerability analysis and patching expert working inside \
a Docker container.

## Your Tools
1. **bash**: Read source code (cat -n), search patterns (rg), explore \
   directories (ls/find), run builds, etc.
2. **str_replace_edit**: Precisely edit source files by replacing exact \
   text. Always read the file first with bash("cat -n <path>") before editing.

## Your Task
Analyse the crash reports below to identify the root cause, then edit the \
source code to fix the vulnerability.

## Workflow

### If a Property Analysis Report is provided:
The report already contains exact file paths, function names, line numbers, \
and the conditions that must hold. TRUST IT and act on it directly:
1. Read ONLY the relevant lines around each property location \
   (e.g. `bash("cat -n <file> | sed -n '<start>,<end>p'")`)
2. Start editing with `str_replace_edit` immediately after reading
3. Address ALL HIGH-confidence properties from the report
4. Only use variables, macros, types, and functions that you have SEEN in \
   the source code you read — NEVER guess or assume any identifier exists

### If NO Property Analysis Report is provided:
1. Extract file:line from the sanitizer stack trace
2. Read the relevant function around the crash site
3. Identify the root cause and start editing promptly

## Patching Guidelines
- Use `str_replace_edit` to make minimal changes that fix the ROOT CAUSE
- Do NOT just mask the crash symptom
- Handle ALL crash paths revealed by the variant PoCs and origin PoC
- Prefer adding safety checks (null checks, bounds checks, type checks) \
  over restructuring code
- Follow the project's existing code style
- Do NOT introduce new bugs or break existing functionality
- Only use identifiers (functions, macros, struct fields, types) that you \
  have confirmed exist in the actual source code — do NOT invent or guess

## Rules
- Read the specific lines before editing (use cat -n with sed line ranges)
- Make the MINIMUM necessary changes
- Do NOT repeatedly read the same file — read once, plan edits, apply them
- CRITICAL: You MUST use the str_replace_edit tool to apply your fix. Do NOT \
  just describe changes verbally. After editing, briefly confirm what you changed.
"""

SELECTOR_SYSTEM_MESSAGE = """\
You are a security patch evaluation expert.

You are given multiple candidate patches that all pass the original PoC \
verification (i.e., after applying each patch, the original PoC no longer \
triggers a sanitizer error).

For each candidate you also receive:
- The patch diff content
- How many PoC variants it was tested against and how many still crashed
- The round number it was generated in

Your task is to select the MOST ROBUST patch based on these criteria \
(in priority order):
1. Variant robustness: the patch that causes the fewest variant PoCs to still crash
2. Root-cause correctness: does the patch fix the actual root cause or just mask symptoms?
3. Minimality: prefer smaller, more focused patches
4. Safety: the patch should not introduce new issues

Output your decision in this exact format:

SELECTED: <candidate_number>
REASON: <brief justification>
"""


# ---------------------------------------------------------------------------
# Agent factory functions
# ---------------------------------------------------------------------------


def create_mutator(
    model_client: OpenAIChatCompletionClient,
    container_id: str,
    *,
    project: str = "",
    num_variants: int = 5,
    poc_path: str = POC_PATH,
    poc_type: str = "binary",
    repro_cmd: str = "",
    ext: str = "",
    targeted: bool = False,
) -> AssistantAgent:
    """Create the Mutator agent with bash tool access.

    Args:
        model_client: The LLM client.
        container_id: Docker container to bind tools to.
        num_variants: Number of variants to generate.
        poc_path: Path to the original PoC inside the container.
        poc_type: One of "text", "binary", "script".
        repro_cmd: The repro command template (with {poc} placeholder).
        ext: File extension for text/script variants (e.g. ".rb").
        targeted: If True, use the targeted mutation prompt (for round > 0).
    """
    bash_tool = make_bash_tool(
        container_id,
        block_builds=_NO_BUILD_BEFORE_VALIDATION,
    )
    view_tool = make_view_tool(container_id)
    search_tool = make_search_tool(container_id, project)
    mutate_poc_tool = make_mutate_poc_tool(container_id)
    run_variant_tool = make_run_variant_tool(container_id, repro_cmd, ext=ext)

    repro_cmd_template = repro_cmd.replace("{poc}", "/tmp/variant_1" + ext)

    fmt_kwargs = dict(
        num_variants=num_variants,
        poc_path=poc_path,
        poc_type=poc_type,
        repro_cmd=repro_cmd,
        repro_cmd_template=repro_cmd_template,
        ext=ext,
    )

    if targeted:
        system_msg = MUTATOR_TARGETED_SYSTEM_MESSAGE.format(**fmt_kwargs)
    else:
        system_msg = MUTATOR_SYSTEM_MESSAGE.format(**fmt_kwargs)

    return AssistantAgent(
        name="Mutator",
        model_client=model_client,
        tools=[view_tool, search_tool, bash_tool, mutate_poc_tool, run_variant_tool],
        system_message=system_msg,
        description="Generates PoC variants to explore vulnerability crash paths.",
        max_tool_iterations=MUTATOR_MAX_TOOL_ITERS,
        reflect_on_tool_use=True,
    )


def create_analyzer(
    model_client: OpenAIChatCompletionClient,
    container_id: str,
    *,
    project: str = "",
    single_crash: bool = False,
    repro_cmd: str = "",
    ext: str = "",
    poc_path: str = POC_PATH,
) -> AssistantAgent:
    """Create the Analyzer agent for property discovery.

    Args:
        model_client: The LLM client.
        container_id: Docker container to bind tools to.
        single_crash: If True, use single-crash analysis prompt (E2 ablation,
                      no variant differential data available).
        repro_cmd: Repro command template with a {poc} placeholder.
        ext: File extension for generated variants.
        poc_path: Path to the original PoC inside the container.
    """
    edit_state = _EditState()
    bash_tool = make_bash_tool(
        container_id,
        block_builds=_NO_BUILD_BEFORE_VALIDATION,
    )
    view_tool = make_view_tool(container_id)
    search_tool = make_search_tool(container_id, project)
    edit_tool = make_str_replace_tool(container_id, edit_state, rewrite_probes=True)
    insert_probe_tool = make_insert_probe_tool(container_id, edit_state)
    revert_last_tool = make_revert_last_edit_tool(container_id, edit_state)
    revert_all_tool = make_revert_all_edits_tool(container_id, edit_state)
    run_probed_tool = make_run_probed_tool(
        container_id,
        repro_cmd,
        ext=ext,
        poc_path=poc_path,
    )

    system_msg = (
        ANALYZER_SINGLE_CRASH_SYSTEM_MESSAGE if single_crash
        else ANALYZER_SYSTEM_MESSAGE
    )

    return AssistantAgent(
        name="Analyzer",
        model_client=model_client,
        tools=[
            view_tool,
            search_tool,
            bash_tool,
            edit_tool,
            insert_probe_tool,
            revert_last_tool,
            revert_all_tool,
            run_probed_tool,
        ],
        system_message=system_msg,
        description="Discovers violated safety properties from crash analysis.",
        max_tool_iterations=ANALYZER_MAX_TOOL_ITERS,
        reflect_on_tool_use=True,
    )


def create_patcher(
    model_client: OpenAIChatCompletionClient,
    container_id: str,
    *,
    project: str = "",
    name: str = "Patcher",
) -> AssistantAgent:
    """Create the Patcher agent (includes analysis + editing).

    The Patcher reads source code with bash, searches with rg, and edits
    files with str_replace_edit.  After it finishes, the pipeline extracts
    the resulting patch via ``git --no-pager diff``.

    Args:
        model_client: The LLM client.
        container_id: Docker container to bind tools to.
        name: Agent name (used for logging, e.g. "Patcher_0").
    """
    edit_state = _EditState()
    bash_tool = make_bash_tool(
        container_id,
        block_builds=_NO_BUILD_BEFORE_VALIDATION,
        block_repro=_NO_BUILD_BEFORE_VALIDATION,
    )
    view_tool = make_view_tool(container_id)
    search_tool = make_search_tool(container_id, project)
    edit_tool = make_str_replace_tool(container_id, edit_state)
    revert_last_tool = make_revert_last_edit_tool(container_id, edit_state)
    revert_all_tool = make_revert_all_edits_tool(container_id, edit_state)
    check_vul_tool = make_check_vul_tool(container_id)
    submit_tool = make_submit_tool(container_id, project)

    return AssistantAgent(
        name=name,
        model_client=model_client,
        tools=[view_tool, search_tool, bash_tool, edit_tool, revert_last_tool, revert_all_tool,
               # check_vul rebuilds the project to run the PoC; under PATCH_MODE metapro and
               # combined the patch is first built only after its PoC validation.
               *([] if _NO_BUILD_BEFORE_VALIDATION else [check_vul_tool]), submit_tool],
        system_message=(
            PATCHER_SYSTEM_MESSAGE.replace(
                "directories (ls/find), run builds, etc.",
                "directories (ls/find). Building the project and running the PoC are "
                "disabled: your patch is validated against the PoC after you submit it.",
            ) if _NO_BUILD_BEFORE_VALIDATION else PATCHER_SYSTEM_MESSAGE
        ),
        description="Analyses crash paths and edits source code to fix memory safety vulnerabilities.",
        max_tool_iterations=PATCHER_MAX_TOOL_ITERS,
        reflect_on_tool_use=True,
    )


def create_selector(
    model_client: OpenAIChatCompletionClient,
) -> AssistantAgent:
    """Create the Selector agent to pick the best patch from candidates."""
    return AssistantAgent(
        name="Selector",
        model_client=model_client,
        system_message=SELECTOR_SYSTEM_MESSAGE,
        description="Evaluates and selects the most robust patch from candidates.",
    )
