#!/bin/bash
###
# Get password, remove trailing \n character and capture with clipboard
# Uncomment the one you prefer
###

###
# Using xsel (Xorg (Linux/BSD) only)
###

# picop get -n $* | head -c -1 | xsel -ib && echo "Copied to clipboard."

###
# Using pyperclip (Cross-platform, requires installing pyperclip package)
###

# picop get -n $* | head -c -1 | python3 -c "__import__('pyperclip').copy(input())" && echo "Copied to clipboard."
