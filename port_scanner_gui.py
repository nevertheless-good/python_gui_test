import tkinter
import tkinter.messagebox
import customtkinter

import nmap
import re

import threading

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
PORT_MIN = 0
PORT_MAX = 65535

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Port Scanner v1.0")
        self.geometry(f"{1100}x{580}")
        self.resizable(False, False)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.ip_address = customtkinter.CTkEntry(self, placeholder_text="IP Address", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.ip_address.grid(row=1, column=1, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.min_port = customtkinter.CTkEntry(self, placeholder_text="Start Port", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.min_port.grid(row=1, column=2, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.continue_label = customtkinter.CTkLabel(self, text="~", anchor="w", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.continue_label.grid(row=1, column=3, padx=(20, 0), pady=(0, 0))

        self.max_port = customtkinter.CTkEntry(self, placeholder_text="End Port", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.max_port.grid(row=1, column=4, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")


        self.start_button = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), font=customtkinter.CTkFont(size=15, weight="bold"))
        self.start_button.grid(row=1, column=5, padx=(20, 20), pady=(20, 20), sticky="nsew")
        self.start_button.configure(text="Start", command=self.start_button_event)

        self.stop_button = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), font=customtkinter.CTkFont(size=15, weight="bold"))
        self.stop_button.grid(row=1, column=6, padx=(20, 20), pady=(20, 20), sticky="nsew")
        self.stop_button.configure(text="Stop", command=self.stop_button_event)


        self.textbox = customtkinter.CTkTextbox(self, width=100, font=customtkinter.CTkFont(size=15, weight="bold"))
        self.textbox.grid(row=2, column=1, columnspan=6, padx=(20, 20), pady=(20, 20), sticky="nsew")

        self.running_status = False

    def port_scan(self, ip_add_entered, port_min, port_max):
        nm = nmap.PortScanner()

        for port in range(int(port_min), int(port_max) + 1):

            if self.running_status == False:
                self.textbox.insert(customtkinter.END, "Stop port scan by User\n")
                break

            try:
                result = nm.scan(ip_add_entered, str(port))
                port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                self.textbox.insert(customtkinter.END, f"Port {port} is {port_status}\n")
            except:
                self.textbox.insert(customtkinter.END, f"Cannot scan port {port}.\n")

            self.textbox.see(customtkinter.END)

        self.textbox.insert(customtkinter.END, "="*100+"\n")
        self.textbox.see(customtkinter.END)


    def start_button_event(self):
        if self.running_status:
            return

        self.running_status = True

        ip_add_entered = self.ip_address.get()
        if not ip_add_pattern.search(ip_add_entered):
            self.textbox.insert(customtkinter.END, f"{ip_add_entered} is not a valid ip address\n")
            self.textbox.insert(customtkinter.END, "="*100+"\n")
            self.textbox.see(customtkinter.END)
            return


        min_port = self.min_port.get()
        max_port = self.max_port.get()
        port_range = min_port + '-' + max_port

        if int(min_port) > int(max_port) or int(min_port) <= PORT_MIN or int(max_port) >= PORT_MAX:
            self.textbox.insert(customtkinter.END, f"Port range({port_range}) is not a valid\n")
            self.textbox.insert(customtkinter.END, "="*100+"\n")
            self.textbox.see(customtkinter.END)
            return

        if not port_range_pattern.search(port_range):
            self.textbox.insert(customtkinter.END, f"Port range({port_range}) is not a valid\n")
            self.textbox.insert(customtkinter.END, "="*100+"\n")
            self.textbox.see(customtkinter.END)
            return

        threading.Thread(target=self.port_scan, args=(ip_add_entered, int(min_port), int(max_port)), daemon=True).start()


    def stop_button_event(self):
        if self.running_status == False:
            return
        else:
            self.running_status = False
            return

if __name__ == "__main__":
    app = App()
    app.mainloop()
