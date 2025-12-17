# Advance / Scenario
# Write a program to count how many lines and words are in a file.

with open("hello.txt", "r") as f:
    for i, line in enumerate(f, start=1):
        pass # What is pass? placeholder that does nothing. basically pass is here just to satisfy python requirement of at least to have one element inisde loop.
    print(f"Number of lines in the file: {i}")
# the counting of the line here is done implicit which seems to be pro way to save memory.
# implicit and explicit
# implicit or automatic way is best way to write python code but it is harder to understand for the beginner.
# explicit or manual way is better for readibility but uses memory to count the numbers.
# implicit way is the best when working with large data.


# with open("hello.txt", "r") as f:
#     lines = f.readlines()
    # first the file hello.txt is opened and read mode to read the all the lines in the file.

# there is readline() and there is readlines() both does different thing here readline reads one line where as the readlines read all lines


with open("hello.txt", "r") as f:
    content = f.read()
    # read() reads entire file content as string.
    # check = content.split()
    word_count = len(content.split())
    # len() is built in python funciton that get the no of items in something
    # split() is built in python funcition separates the words where the spaces are.
    # print(check)
    # print(word_count)
print(f"Number of words: {word_count}")

