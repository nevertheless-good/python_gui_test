import tkinter
import tkinter.messagebox
import customtkinter

import nmap
import re

import threading

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Port Scanner v1.0")
        self.geometry(f"{1100}x{580}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        # self.grid_columnconfigure(2, weight=0)
        self.grid_rowconfigure(2, weight=1)


        # create main entry and button
        self.ip_address = customtkinter.CTkEntry(self, placeholder_text="IP Address")
        self.ip_address.grid(row=1, column=1, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.min_port = customtkinter.CTkEntry(self, placeholder_text="Start Port")
        self.min_port.grid(row=1, column=2, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.continue_label = customtkinter.CTkLabel(self, text="~", anchor="w")
        self.continue_label.grid(row=1, column=3, padx=(20, 0), pady=(0, 0))        

        self.max_port = customtkinter.CTkEntry(self, placeholder_text="End Port")
        self.max_port.grid(row=1, column=4, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")


        self.start_button = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.start_button.grid(row=1, column=5, padx=(20, 20), pady=(20, 20), sticky="nsew")
        self.start_button.configure(text="Start", command=self.start_button_event)

        self.stop_button = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.stop_button.grid(row=1, column=6, padx=(20, 20), pady=(20, 20), sticky="nsew")
        self.stop_button.configure(text="Stop", command=self.stop_button_event)


        self.textbox = customtkinter.CTkTextbox(self, width=100)
        self.textbox.grid(row=2, column=1, columnspan=6, padx=(20, 20), pady=(20, 20), sticky="nsew")

       
    def port_scan(self, ip_add_entered, port_min, port_max):
        nm = nmap.PortScanner()
        
        for port in range(int(port_min), int(port_max) + 1):
            try:
                result = nm.scan(ip_add_entered, str(port))
                port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                print(f"Port {port} is {port_status}")
                self.textbox.insert("0.0", f"Port {port} is {port_status}\n")
            except:
                print(f"Cannot scan port {port}.")
                self.textbox.insert("0.0", f"Cannot scan port {port}.\n")

        self.textbox.insert("0.0", "="*100+"\n")


    def start_button_event(self):
        ip_add_entered = self.ip_address.get()
        if ip_add_pattern.search(ip_add_entered):
            print(f"{ip_add_entered} is a valid ip address")
        else:
            self.textbox.insert("0.0", f"{ip_add_entered} is not a valid ip address\n")
            self.textbox.insert("0.0", "="*100+"\n")
            return


        port_min = self.min_port.get()
        port_max = self.max_port.get()
        port_range = port_min + '-' + port_max
        if port_range_pattern.search(port_range):
             print(f"{port_range} is a valid")
        else:
            self.textbox.insert("0.0", f"{port_range} is not a valid\n")
            self.textbox.insert("0.0", "="*100+"\n")
            return

        threading.Thread(target=self.port_scan, args=(ip_add_entered, int(port_min), int(port_max)), daemon=True).start()


    def stop_button_event(self):
        print("stop_button_event:")        


if __name__ == "__main__":
    app = App()
    app.mainloop()
