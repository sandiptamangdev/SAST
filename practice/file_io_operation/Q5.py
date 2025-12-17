# Line-Based Operations.
# Read `number.txt` line by line and print each line with it's line number.

# if there is line by line then use loop.
# if there is line number then use enumerate.
# .strip() is same as .trim() in js that removes the spaces in the front and back of the sentence, word.


# open the file 'number.txt' in read mode.
# Using 'with' auto closes the file after use.
# f is a variable that you can name anything here.
with open("number.txt", "r") as f:
    # enumerate() lets the loop line by line And gives a counter
    # what do you mean by gives a counter
    # so enumerate() basically is a counter itself

    # for i, line in enumerate(f, start=1):
        # print(f"{i}: {line.strip()}")

    # count = 1
    # for line in f:
    #     print(count, line)
    #     count += 1
    
    # there is an issue with this this gives a gap of 1 line between the outputs.
    # the use of strip() here was became clear why as it was used to remove a new line. as both the line had \n and the print also has \n so use of strip() to remove the extra line.

    count = 1
    for line in f:
        print(count, line.strip())
        count += 1

    # so using enumerate() instead of this was just to have less lines of code and to also have the code have less path of error.

    # the pros and cons of using enumurate() vs custom counter
        # enumurate
            # pros
                # clean and less code
                # less chance of bugs
                # flexible staring index 
                # works with any iterable, not just files.
            # cons
                # sligntly less transparent if your beginner
        
        # custom counter
            # pros
                # very explicit
                # easy to modify (double or skip numbers);
            # cons
                # more code
                # slightly less pythonic --not the best way to write python code.