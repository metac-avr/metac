import tree_sitter as ts


def traverse_two_tree(node1: ts.Node, node2: ts.Node):
    continue_traverse = True
    # TODO: Now we just interrupt traversal if they are mismatch, add more logic to find the patch pattern
    if node1.type != node2.type:
        print(f"Node type mismatch: {node1.type} != {node2.type}")
        continue_traverse = False
    if node1.value != node2.value:
        print(f"Node value mismatch: {node1.value} != {node2.value}")
        continue_traverse = False
    
    for child1, child2 in zip(node1.named_children, node2.named_children):
        continue_traverse = traverse_two_tree(child1, child2)
        if not continue_traverse:
            break
    return continue_traverse
