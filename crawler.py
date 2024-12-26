import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import requests
from bs4 import BeautifulSoup
import nmap
import platform
import socket

# Function to crawl the entered websites and extract data
def crawl_websites():
    urls = url_entry.get("1.0", tk.END).strip().split('\n')
    all_data = []
    progress_bar['maximum'] = len(urls)

    for i, url in enumerate(urls):
        progress_bar['value'] = i + 1
        progress_bar.update()
        if not url.startswith('http'):
            url = 'http://' + url
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                page_data = {
                    'URL': url,
                    'Title': soup.title.string if soup.title else 'No title',
                    'Headings': [heading.text for heading in soup.find_all(['h1', 'h2', 'h3'])],
                    'Paragraphs': [para.text for para in soup.find_all('p')],
                    'Links': [a['href'] for a in soup.find_all('a', href=True)],
                    'Media': [tag['src'] for tag in soup.find_all(['img', 'audio', 'video'], src=True)]
                }
                all_data.append(page_data)
            else:
                all_data.append({'URL': url, 'Error': 'Failed to retrieve'})
        except Exception as e:
            all_data.append({'URL': url, 'Error': str(e)})

    # Perform network scans for each domain
    nm = nmap.PortScanner()
    for data in all_data:
        if 'Error' in data:
            continue
        domain = data['URL'].replace('http://', '').replace('https://', '').split('/')[0]
        try:
            ip_address = socket.gethostbyname(domain)
            os_info = platform.system() + ' ' + platform.release()
            scan_result = nm.scan(ip_address, '22-443')
            data['IP Address'] = ip_address
            data['OS Info'] = os_info
            data['Port Scan'] = scan_result['scan'][ip_address]['tcp']
        except Exception as e:
            data['Network Scan Error'] = str(e)

    # Display the results in the text output in a readable format
    output_field.delete("1.0", tk.END)
    for data in all_data:
        output_field.insert(tk.END, f"URL: {data['URL']}\n")
        if 'Error' in data:
            output_field.insert(tk.END, f"Error: {data['Error']}\n")
        else:
            output_field.insert(tk.END, f"Title: {data['Title']}\n")
            output_field.insert(tk.END, "Headings:\n")
            for heading in data['Headings']:
                output_field.insert(tk.END, f"  - {heading}\n")
            output_field.insert(tk.END, "Paragraphs:\n")
            for para in data['Paragraphs']:
                output_field.insert(tk.END, f"  - {para}\n")
            output_field.insert(tk.END, "Links:\n")
            for link in data['Links']:
                output_field.insert(tk.END, f"  - {link}\n")
            output_field.insert(tk.END, "Media:\n")
            for media in data['Media']:
                output_field.insert(tk.END, f"  - {media}\n")
            if 'IP Address' in data:
                output_field.insert(tk.END, f"IP Address: {data['IP Address']}\n")
                output_field.insert(tk.END, f"OS Info: {data['OS Info']}\n")
                output_field.insert(tk.END, "Port Scan:\n")
                for port, details in data['Port Scan'].items():
                    output_field.insert(tk.END, f"  - Port {port}: {details['state']}\n")
        output_field.insert(tk.END, "\n")

    progress_bar['value'] = 0  # Reset the progress bar

# Function to exit the application
def exit_app():
    root.quit()

# Create the main window
root = tk.Tk()
root.title("Advanced Web Crawler with Network Scanning")
root.geometry("600x600")

# Create a menu
menu = tk.Menu(root)
root.config(menu=menu)

def show_about():
    messagebox.showinfo("About", "This is an advanced web crawler application to extract various types of data from webpages and perform basic network scanning.")

# Add menu items
file_menu = tk.Menu(menu)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="About", command=show_about)
file_menu.add_command(label="Exit", command=exit_app)

# Create a toolbar
toolbar_top = tk.Frame(root, bd=1, relief=tk.RAISED)
crawl_button = tk.Button(toolbar_top, text="Crawl Websites", command=crawl_websites)
crawl_button.pack(side=tk.LEFT, padx=2, pady=2)
toolbar_top.pack(side=tk.TOP, fill=tk.X)

# Create entry field for the URLs
url_label = tk.Label(root, text="Enter URLs (one per line):")
url_label.pack(pady=5)
url_entry = tk.Text(root, height=10, width=60)
url_entry.pack(pady=5, expand=True, fill=tk.BOTH)

# Create a progress bar
progress_bar = ttk.Progressbar(root, orient='horizontal', mode='determinate')
progress_bar.pack(pady=5, fill=tk.X)

# Create a text field to display the results
output_label = tk.Label(root, text="Extracted Data:")
output_label.pack(pady=5)
output_field = tk.Text(root, height=15, width=60)
output_field.pack(pady=5, expand=True, fill=tk.BOTH)

# Run the GUI event loop
root.mainloop()
