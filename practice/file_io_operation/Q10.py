# Advacned/ Scenario
# Write a program that copies content from `source.txt` to `destination.txt`.

# made the source.txt and added some content.
# with open("source.txt", 'w') as f:
#     f.write("This is cool")

# made the destination.txt file
# with open("destination.txt", 'w') as f:
#     f.write()
# this is bad way to create a file as it creates error as write can't be empty and requrires something to write.

# with open("destination.txt", 'w') as f:
#     pass
# best way to make an empty file.

with open("source.txt", "r") as f:
    content = f.read()
    print(content)

with open("destination.txt", 'w') as f:
    f.write(content)

with open("destination.txt", 'r') as f:
    print(f.read())