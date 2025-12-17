# Basic File Operation.
# Create a file name `example.txt` and write `"Hello World"` to it.

with open("example.txt", "w") as f:
    f.write("hello")
# w is a mode which means write there are five modes w, r, a, rb, rw. rb and rw are read and write in binary. 
# "with" will close the file auto after it completes the operation.
# 'f' is the variable you can use anything.
# 'as' is way to make use of temporary variables.
#  open() is built in funciton that opens the file in any mode that you asked it w r or a.
#  write() is also a built in funciton that helps to write in the opened file but here it can do two things according to how you open the file, if you open with a = append then it will add to the existing ones where as if it is opened with w = then it will replace any file there and write what you wrote.
