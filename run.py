import tkinter as tk
from tkinter import messagebox
import subprocess

# Function to run a Python file
def run_file(file_name):
    subprocess.run(['python', file_name])

# Function to exit the application
def exit_app():
    root.quit()

# Create the main window
root = tk.Tk()
root.title("Enhanced GUI for Running Python Files")
root.geometry("600x400")  # Set the window size

# Create a menu
menu = tk.Menu(root)
root.config(menu=menu)

def show_about():
    messagebox.showinfo("About", "Trust is the weapon of SMART\n and the life of a FOOL")

# Add menu items
file_menu = tk.Menu(menu)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="About", command=show_about)
file_menu.add_command(label="Exit", command=exit_app)

# Create the first toolbar
toolbar_top = tk.Frame(root, bd=1, relief=tk.RAISED)
button1 = tk.Button(toolbar_top, text="Port Scanner", command=lambda: run_file('networkscan.py'))
button1.pack(side=tk.LEFT, padx=2, pady=2)
button2 = tk.Button(toolbar_top, text="SQL Injection", command=lambda: run_file('sqlbug.py'))
button2.pack(side=tk.LEFT, padx=2, pady=2)
toolbar_top.pack(side=tk.TOP, fill=tk.X)

# Create the second toolbar and place it below the first toolbar
toolbar_middle = tk.Frame(root, bd=1, relief=tk.RAISED)
button3 = tk.Button(toolbar_middle, text="XSS", command=lambda: run_file('xssbug.py'))
button3.pack(side=tk.LEFT, padx=2, pady=2)
button4 = tk.Button(toolbar_middle, text="Crawler", command=lambda: run_file('crawler.py'))
button4.pack(side=tk.LEFT, padx=2, pady=2)
toolbar_middle.pack(side=tk.TOP, fill=tk.X)

# Create a text field for the introduction
introduction = """Welcome to the Python File Runner!
Click the buttons above to run the respective Python files.
This tool is designed to make your workflow easier."""

text_field = tk.Text(root, height=10, width=60)
text_field.insert(tk.END, introduction)
text_field.pack(pady=20, expand=True, fill=tk.BOTH)

# Run the GUI event loop
root.mainloop()
