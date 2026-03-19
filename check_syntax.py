import ast
import os

def check_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    tree = ast.parse(content)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    # Check if there's a backslash in the expression part
                    # Note: FormattedValue.value is the expression
                    pass
    # Actually, ast.parse would HAVE FAILED if there was a SyntaxError.
    print("No SyntaxError found by ast.parse")

try:
    check_file('desktop/main.py')
except SyntaxError as e:
    print(f"SyntaxError found: {e}")
except Exception as e:
    print(f"Error: {e}")
