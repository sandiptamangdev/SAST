# Basic File Operations.
# Open `example.txt` and read its content. Print it.

with open("example.txt", "r") as f:
#     content = f.read()
# print(content)
    print(f.read())