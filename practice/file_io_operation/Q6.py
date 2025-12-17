# Line-Based Operation
# Read all lines into a list and print the list.

with open("number.txt", "r") as f:
    # readlines is a built in method of file object  in python.
    # It's job basically is to make a list of the each line into a string of the list.
    # It also adds the \n in the list which can be removed with strip().

    # lines = f.readlines()
    # print(lines)

    lines = [line.strip() for line in f]
    # list in python are [] made.
    # why does it know lines line is the 1 line then?
        # line is a temporary var that is used to store the line of of the lines in the file to make it into the list.  
    print(lines)


    
