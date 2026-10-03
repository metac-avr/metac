# MetaC

This repository contains a replication package and experiment data for the paper "Accelerating Automated Vulnerability Repair via Metaprogramming", submitted to FSE 2027.

## Directories and files

```
metac/
├── README.md
├── install-deps.sh            # Installs system dependencies (LLVM/Clang 12, build tools, Python packages)
├── checkout.sh                # Initializes and updates git submodules
├── build.sh                   # Builds tree-sitter and MetaC (metapro)
├── setup_llvm.py              # Sets up LLVM/Clang 12 tool aliases
├── requirements.txt           # Python dependencies
├── config.template.json       # Configuration template for experiments
│
├── metapro/                   # Meta-program generator (source-level instrumentation)
├── san2patch/                 # San2Patch: existing AVR tool used in our evaluation
├── contrafix/                 # ContraFix: existing AVR tool used in our evaluation
│
├── benchmarks/
│   └── arvo/                  # ARVO benchmark and experiment data
│       ├── projects/          #   Subject projects (ffmpeg, gpac, libxml2, mruby, ndpi, php)
│       ├── scripts/           #   Scripts to run experiments (RQ1-RQ4) and draw figures
│       ├── overview.csv       #   Overview of benchmark vulnerabilities from ARVO
│       ├── rq*.json           #   Experiment results
│       └── rq*.pdf            #   Figures in the paper
│
├── dyninst/                   # DynInst: dynamic binary patching tool used in our evaluation
├── dyninst-poc/               # Dyninst-based function replacer (mutator_launch)
└── py-tree-sitter/            # Modified Python bindings for tree-sitter
```

In each bug directory under `benchmarks/arvo/projects/<project>/<bug_id>`, we store the required files and scripts.
The `san2patch*` and `contrafix*` directories contain the raw data from our evaluation.

## Setup

### Prerequisites

* Ubuntu 20.04
* Anaconda or Miniconda with Python 3.10+
* Docker-out-of-Docker (DooD)
* An API key for the LLM

DooD is required to run our tool with the ARVO benchmark.

First, copy `config.template.json` to `config.json`.
This file configures the mount point used to create containers for the ARVO benchmark.
Configuring it is strongly recommended to avoid disk bloat.

Run `install-deps.sh` to install the dependencies.
Run `pip3 install -r requirements.txt` to install the Python dependencies.
After running them, run `python setup_llvm.py`.
This will set up LLVM and Clang in this environment.

Finally, run `build.sh` to build the submodules in this repo.

## Reproducing our experiments

To reproduce our evaluation, see `rq*.py` in `benchmarks/arvo/scripts`.
They reproduce the results for the RQs in our paper.

### Before reproducing the experiments

Before running `rq*.py`, you must run the following:
```
python3 checkout.py [options]
python3 test-container.py [options]
python3 run-metapro-binary.py [options]
```

`checkout.py` will pull the Docker images for ARVO from Docker Hub and create the containers.
Be careful about disk usage.
`test-container.py` will run the buggy version of each bug and get the output of the PoC test.
`run-metapro-binary.py` will run source code instrumentation and generate the instrumented binaries.

### RQ 1, 2 and 3

Run `run-san2patch.py` or `run-contrafix.py` to generate plausible patches.

For RQ1 and 2, run `rq1-2-*.py` to run each method.
After that, run `rq1-*-boxplot.py` to generate the boxplots used in RQ1.
Run `rq2-metac-*-result.py` to get the results for RQ2.

Each `rq1-2-*.py` will also generate the plots used in RQ3.

### RQ 4

Run `rq4-san2patch/contrafix.py` to run each AVR tool end-to-end.
After that, run `rq4-*-boxplot.py` to get the plots used in RQ4.