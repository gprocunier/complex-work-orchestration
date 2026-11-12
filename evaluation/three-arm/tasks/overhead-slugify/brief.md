`slugify("")` in textutil/slug.py raises IndexError. Make it return an empty
string, and add a unit test for that case under tests/.
