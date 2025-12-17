# File Modes Practice
# Open a file in `"w"` mode, write some text, then read it. What happens?

with open("hello.txt", "w") as f:
    f.write("Hello World!")


with open("hello.txt", "r") as f:
    print(f.read())