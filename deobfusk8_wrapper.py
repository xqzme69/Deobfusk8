import sys
import os
import time

# Enable ANSI escape codes on Windows
if os.name == 'nt':
    os.system("")

from deobfusk8.cli import main

BANNER = r"""
=============================================================================
 ██████╗ ███████╗██████╗ ██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗ █████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██║ ██╔╝██╔══██╗
 ██║  ██║█████╗  ██║  ██║██████╔╝█████╗  ██║   ██║███████╗█████╔╝ ╚█████╔╝
 ██║  ██║██╔══╝  ██║  ██║██╔══██╗██╔══╝  ██║   ██║╚════██║██╔═██╗ ██╔══██╗
 ██████╔╝███████╗██████╔╝██████╔╝██║     ╚██████╔╝███████║██║  ██╗╚█████╔╝
 ╚═════╝ ╚══════╝╚═════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚════╝ 
=============================================================================
"""

def animate_sub_banner():
    # Clear screen first
    os.system('cls' if os.name == 'nt' else 'clear')
    sys.stdout.write(BANNER)
    sys.stdout.flush()
    
    sub1 = "         > :: Static Obfusk8 String & API Extractor :: <\n"
    sub2 = "         > ::        Created by xqzme                :: <\n"
    sub3 = "=============================================================================\n"
    
    for char in sub1:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.01)
        
    for char in sub2:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.02)
        
    for char in sub3:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.005)

def print_menu():
    print("\n[ Main Menu ]")
    print("1. Select Binary (Opens Explorer)")
    print("2. View CLI Commands & Help")
    print("3. Exit")
    print("")

def run_deobfusk8(args):
    # Backup original argv
    original_argv = sys.argv[:]
    try:
        # Patch argv for the tool
        sys.argv = ["deobfusk8"] + args
        main()
    except SystemExit as e:
        # Prevent argparse --help from closing our menu loop
        pass
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
    except Exception as e:
        print(f"\n[!] Error during execution: {e}")
    finally:
        sys.argv = original_argv
        input("\nPress Enter to return to Main Menu...")

def main_loop():
    while True:
        animate_sub_banner()
        print_menu()
        
        try:
            choice = input("deobfusk8> ").strip()
        except KeyboardInterrupt:
            print()
            break
            
        if choice == '1':
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                # Ensure dialog sits on top
                root.attributes("-topmost", True)
                file_path = filedialog.askopenfilename(
                    title="Select PE64 binary to deobfuscate",
                    filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
                )
                if file_path:
                    print(f"\n[*] Selected: {file_path}")
                    run_deobfusk8([file_path])
                else:
                    print("\n[!] No file selected.")
                    time.sleep(1)
            except Exception as e:
                print(f"\n[!] Could not open file dialog: {e}")
                time.sleep(2)
                
        elif choice == '2':
            print("\n")
            run_deobfusk8(["--help"])
            
        elif choice == '3':
            print("\nExiting...")
            break
        else:
            print("\n[!] Invalid option. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    main_loop()
    if getattr(sys, 'frozen', False):
        time.sleep(1)
