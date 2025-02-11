import requests
import argparse
import threading
import queue
import sys
import os
from termcolor import colored

# ASCII Art for the tool name
def print_banner():
    banner = """
  
 /$$$$$$$                        /$$                               /$$$$$$           
| $$__  $$                      | $$                              /$$$_  $$          
| $$  \ $$  /$$$$$$   /$$$$$$  /$$$$$$        /$$   /$$  /$$$$$$$| $$$$\ $$  /$$$$$$ 
| $$$$$$$/ /$$__  $$ /$$__  $$|_  $$_//$$$$$$|  $$ /$$/ /$$_____/| $$ $$ $$ /$$__  $$
| $$__  $$| $$  \ $$| $$  \ $$  | $$ |______/ \  $$$$/ |  $$$$$$ | $$\ $$$$| $$  \__/
| $$  \ $$| $$  | $$| $$  | $$  | $$ /$$       >$$  $$  \____  $$| $$ \ $$$| $$      
| $$  | $$|  $$$$$$/|  $$$$$$/  |  $$$$/      /$$/\  $$ /$$$$$$$/|  $$$$$$/| $$      
|__/  |__/ \______/  \______/    \___/       |__/  \__/|_______/  \______/ |__/      
                                                                                     
                                                                                     
                                                                                    
    print(colored(banner, "cyan"))
    print(colored("Created by: Mian Hammad", "yellow"))
    print(colored("LinkedIn: https://www.linkedin.com/in/mian-hammad-8334b1228/", "yellow"))

def load_payloads():
    try:
        with open("payload.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(colored("[ERROR] payload.txt file not found!", "red"))
        sys.exit(1)

def test_xss(url, payload):
    test_url = url.replace("{payload}", payload)
    try:
        response = requests.get(test_url, timeout=5, verify=False)
        if payload in response.text:
            print(colored(f"[VULNERABLE] {test_url}", "green"))
            return test_url
        else:
            print(colored(f"[NOT VULNERABLE] {test_url}", "red"))
    except requests.RequestException as e:
        print(colored(f"[ERROR] Failed to connect to {test_url}: {e}", "red"))
    return None

def worker(queue, output_file):
    payloads = load_payloads()
    while not queue.empty():
        url = queue.get()
        for payload in payloads:
            result = test_xss(url, payload)
            if result and output_file:
                with open(output_file, "a") as f:
                    f.write(result + "\n")
        queue.task_done()

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Root-Xs0r - Advanced XSS Finder Tool")
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5, max: 10)")
    parser.add_argument("-o", "--output", help="File to save vulnerable URLs")
    args = parser.parse_args()
    
    if args.threads > 10:
        print(colored("[ERROR] Maximum thread limit is 10!", "red"))
        sys.exit(1)
    
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(colored("[ERROR] URL list file not found!", "red"))
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    url_queue = queue.Queue()
    for url in urls:
        url_queue.put(url)
    
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(url_queue, args.output))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    print(colored("[INFO] Scan completed!", "blue"))

if __name__ == "__main__":
    main()
