import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests

# --- Configuration ---
API_DOMAIN = "http://127.0.0.1:8000"
API_BASE_URL = f"{API_DOMAIN}/api/v1"
API_ASSET_URL = f"{API_BASE_URL}/assets"
API_LOGIN_URL = f"{API_BASE_URL}/login/token"
API_USERS_URL = f"{API_BASE_URL}/users"
API_CATEGORIES_URL = f"{API_BASE_URL}/categories"
API_LOCATIONS_URL = f"{API_BASE_URL}/locations"
API_DEPARTMENTS_URL = f"{API_BASE_URL}/departments"

# --- Login Window (Unchanged) ---
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("ByteBolt Login")
        self.root.geometry("300x150")
        self.root.eval('tk::PlaceWindow . center')
        
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.main_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_entry = ttk.Entry(self.main_frame)
        self.user_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.main_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pass_entry = ttk.Entry(self.main_frame, show="*")
        self.pass_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_btn = ttk.Button(self.main_frame, text="Login", command=self.login)
        self.login_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.root.bind('<Return>', lambda e: self.login())
        self.user_entry.focus_set()
        self.login_data = None

    def login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        try:
            login_payload = {'username': username, 'password': password}
            response = requests.post(API_LOGIN_URL, data=login_payload)
            
            if response.status_code == 200:
                token_data = response.json()
                self.login_data = {"token": token_data.get("access_token")}
                headers = {"Authorization": f"Bearer {self.login_data['token']}"}
                user_me_response = requests.get(f"{API_BASE_URL}/login/me", headers=headers)
                
                if user_me_response.status_code == 200:
                    user_data = user_me_response.json()
                    self.login_data["user"] = user_data
                    self.root.destroy()
                else:
                    messagebox.showerror("Login Error", f"Could not fetch user details: {user_me_response.text}")
                    self.login_data = None
            else:
                messagebox.showerror("Login Failed", f"Error: {response.json().get('detail', 'Invalid credentials')}")
                self.login_data = None
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not connect to server: {e}")
            self.login_data = None

# --- Main Application (Modified) ---
class ByteBoltApp:
    def __init__(self, root, token, user):
        self.root = root
        self.root.title(f"ByteBolt - IT Multi-App (User: {user['username']} | Role: {user['role']})")
        self.root.geometry("1400x700")
        
        self.token = token
        self.user = user
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

        self.category_map = {}
        self.location_map = {}
        self.department_map = {}

        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Calibri', 10, 'bold'))
        style.configure("Danger.TButton", foreground="red")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.asset_tab_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.asset_tab_frame, text="Asset Registry")
        
        if self.user['role'] == 'admin':
            self.settings_tab_frame = ttk.Frame(self.notebook, padding="10")
            self.notebook.add(self.settings_tab_frame, text="Settings")
        
        self.load_all_dropdown_data()
        
        if self.user['role'] == 'admin':
            self.create_settings_tab_widgets()
        
        self.create_asset_tab_widgets()
        self.load_assets()
        self.apply_asset_permissions()

    def apply_asset_permissions(self):
        if self.user['role'] == 'view':
            self.add_btn.config(state="disabled")
            self.update_btn.config(state="disabled")
            self.delete_btn.config(state="disabled")
            self.decommission_btn.config(state="disabled")
            self.reinstate_btn.config(state="disabled")
        elif self.user['role'] == 'edit':
            self.delete_btn.config(state="disabled")

    def create_asset_tab_widgets(self):
        # --- Form (Left Side) ---
        
        form_container = ttk.LabelFrame(self.asset_tab_frame, text="Asset Details", padding="10")
        # --- [MODIFIED] Set a fixed width and fill=Y ---
        form_container.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=5, width=400)
        form_container.pack_propagate(False) # Stop frame from shrinking to contents

        # --- [NEW] Scrollable Canvas setup ---
        canvas = tk.Canvas(form_container, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(form_container, orient="vertical", command=canvas.yview)
        self.scrollable_form_frame = ttk.Frame(canvas)

        self.scrollable_form_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_form_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # --- Mousewheel locking ---
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        canvas.bind('<Enter>', _bind_mousewheel)
        canvas.bind('<Leave>', _unbind_mousewheel)

        # --- [MODIFIED] Single-column form layout ---
        self.form_fields = {}
        all_fields = [
            "Serial Number", "Device Name", "Make", "Model", 
            "Category", "Location", "Department", 
            "Allocated User", "IP Address", "Value (ZAR)"
        ]
        
        row_index = 0
        for field in all_fields:
            label = ttk.Label(self.scrollable_form_frame, text=f"{field}:")
            label.grid(row=row_index, column=0, sticky=tk.W, pady=2, padx=5)
            
            if field == "Category":
                self.asset_category_var = tk.StringVar()
                widget = ttk.Combobox(self.scrollable_form_frame, textvariable=self.asset_category_var, 
                                      values=list(self.category_map.keys()), state="normal", width=38)
                self.asset_category_combo = widget # Save reference for updating
            elif field == "Location":
                self.asset_location_var = tk.StringVar()
                widget = ttk.Combobox(self.scrollable_form_frame, textvariable=self.asset_location_var, 
                                      values=list(self.location_map.keys()), state="normal", width=38)
                self.asset_location_combo = widget # Save reference
            elif field == "Department":
                self.asset_department_var = tk.StringVar()
                widget = ttk.Combobox(self.scrollable_form_frame, textvariable=self.asset_department_var, 
                                      values=list(self.department_map.keys()), state="normal", width=38)
                self.asset_department_combo = widget # Save reference
            else:
                widget = ttk.Entry(self.scrollable_form_frame, width=40)
                self.form_fields[field] = widget
            
            widget.grid(row=row_index, column=1, sticky=tk.EW, pady=2, padx=5)
            row_index += 1

        button_frame = ttk.Frame(self.scrollable_form_frame)
        button_frame.grid(row=row_index, column=0, columnspan=2, pady=10)
        row_index += 1
        
        self.add_btn = ttk.Button(button_frame, text="Add Asset", command=self.add_asset)
        self.add_btn.pack(side=tk.LEFT, padx=5)
        self.update_btn = ttk.Button(button_frame, text="Update Selected", command=self.update_asset)
        self.update_btn.pack(side=tk.LEFT, padx=5)
        self.delete_btn = ttk.Button(button_frame, text="Delete Selected", command=self.delete_asset, style="Danger.TButton")
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(button_frame, text="Clear Form", command=self.clear_form)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # --- [NEW] Decommission/Reinstate Buttons ---
        status_button_frame = ttk.Frame(self.scrollable_form_frame)
        status_button_frame.grid(row=row_index, column=0, columnspan=2, pady=5)
        row_index += 1
        self.decommission_btn = ttk.Button(status_button_frame, text="Decommission", command=lambda: self.set_asset_status("decommissioned"))
        self.decommission_btn.pack(side=tk.LEFT, padx=5)
        self.reinstate_btn = ttk.Button(status_button_frame, text="Reinstate", command=lambda: self.set_asset_status("active"))
        self.reinstate_btn.pack(side=tk.LEFT, padx=5)
        # --- End of Form ---

        # --- List (Right Side) ---
        list_frame = ttk.LabelFrame(self.asset_tab_frame, text="Asset List", padding="10")
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=5)

        # --- [MODIFIED] New Search/Filter Bar Layout ---
        self.filter_entries = {} 
        
        # Bar 1: Search Bar
        search_frame = ttk.Frame(list_frame, padding=(0, 5))
        search_frame.pack(fill=tk.X)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(5, 2))
        search_entry = ttk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.filter_entries['search_term'] = search_entry

        # Bar 2: Filter Bar
        filter_frame = ttk.Frame(list_frame, padding=(0, 5))
        filter_frame.pack(fill=tk.X)
        
        # --- [NEW] Status Filter ---
        ttk.Label(filter_frame, text="Status:").pack(side=tk.LEFT, padx=(5, 2))
        status_combo = ttk.Combobox(filter_frame, values=["All", "Active", "Decommissioned"], width=15, state="readonly")
        status_combo.set("Active") # Default to Active
        status_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.filter_entries['status_filter'] = status_combo
        
        dropdown_filters = {"Category": "category", "Location": "location", "Department": "department"}
        for display_name, internal_name in dropdown_filters.items():
            ttk.Label(filter_frame, text=f"{display_name}:").pack(side=tk.LEFT, padx=(5, 2))
            
            if internal_name == 'category': values = list(self.category_map.keys())
            elif internal_name == 'location': values = list(self.location_map.keys())
            else: values = list(self.department_map.keys())
                
            combo = ttk.Combobox(filter_frame, values=values, width=20)
            combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            self.filter_entries[internal_name] = combo 
        
        # Bar 3: Button Bar
        button_bar_frame = ttk.Frame(list_frame, padding=(0, 5))
        button_bar_frame.pack(fill=tk.X)

        self.search_btn = ttk.Button(button_bar_frame, text="Search / Filter", command=self.load_assets)
        self.search_btn.pack(side=tk.LEFT, padx=5)
        self.clear_filter_btn = ttk.Button(button_bar_frame, text="Clear All", command=self.clear_filters)
        self.clear_filter_btn.pack(side=tk.LEFT, padx=5)
        # --- End of Search/Filter Layout ---

        # --- [MODIFIED] Asset List (Treeview) with all columns ---
        self.tree_columns = (
            "id", "status", "device_name", "serial_number", "category", "location", 
            "department", "allocated_user", "make", "model", "ip_address", "value_zar"
        )
        self.tree = ttk.Treeview(list_frame, columns=self.tree_columns, show="headings")
        
        for col in self.tree_columns:
            self.tree.heading(col, text=col.replace("_", " ").title())
            
        self.tree.column("id", width=40, anchor=tk.CENTER)
        self.tree.column("status", width=80, anchor=tk.CENTER) # <--- NEW
        self.tree.column("device_name", width=140)
        self.tree.column("serial_number", width=120)
        self.tree.column("category", width=100)
        self.tree.column("location", width=120)
        self.tree.column("department", width=100)
        self.tree.column("allocated_user", width=120)
        self.tree.column("make", width=100)
        self.tree.column("model", width=100)
        self.tree.column("ip_address", width=110)
        self.tree.column("value_zar", width=100, anchor=tk.E)

        yscroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y); xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_asset_select)
        
    def create_settings_tab_widgets(self):
        settings_notebook = ttk.Notebook(self.settings_tab_frame)
        settings_notebook.pack(fill=tk.BOTH, expand=True)

        self.user_admin_tab = ttk.Frame(settings_notebook, padding="10")
        self.app_custom_tab = ttk.Frame(settings_notebook, padding="10")
        self.server_settings_tab = ttk.Frame(settings_notebook, padding="10")
        self.dropdown_admin_tab = ttk.Frame(settings_notebook, padding="10")

        settings_notebook.add(self.user_admin_tab, text="User Management")
        settings_notebook.add(self.dropdown_admin_tab, text="Dropdown Management")
        settings_notebook.add(self.app_custom_tab, text="Application Customization")
        settings_notebook.add(self.server_settings_tab, text="Server Settings")

        self.populate_user_admin_tab()
        self.populate_dropdown_admin_tab()
        self.populate_app_custom_tab()
        self.populate_server_settings_tab()
        
    def populate_user_admin_tab(self):
        main_admin_frame = ttk.Frame(self.user_admin_tab)
        main_admin_frame.pack(fill=tk.BOTH, expand=True)
        user_list_frame = ttk.LabelFrame(main_admin_frame, text="User List", padding="10")
        user_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.user_tree = ttk.Treeview(user_list_frame, columns=("id", "username", "role"), show="headings")
        self.user_tree.heading("id", text="ID"); self.user_tree.heading("username", text="Username"); self.user_tree.heading("role", text="Role")
        self.user_tree.column("id", width=50, anchor=tk.CENTER)
        self.user_tree.pack(fill=tk.BOTH, expand=True)
        self.user_tree.bind("<<TreeviewSelect>>", self.on_user_select)
        user_mgmt_frame = ttk.Frame(main_admin_frame, padding="10")
        user_mgmt_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        create_frame = ttk.LabelFrame(user_mgmt_frame, text="Create New User", padding="10")
        create_frame.pack(fill=tk.X, pady=5)
        ttk.Label(create_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.create_user_entry = ttk.Entry(create_frame)
        self.create_user_entry.grid(row=0, column=1, pady=2, padx=5)
        ttk.Label(create_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.create_pass_entry = ttk.Entry(create_frame, show="*")
        self.create_pass_entry.grid(row=1, column=1, pady=2, padx=5)
        ttk.Label(create_frame, text="Role:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.create_role_var = tk.StringVar(value="view")
        self.create_role_menu = ttk.Combobox(create_frame, textvariable=self.create_role_var, values=["view", "edit", "admin"], state="readonly")
        self.create_role_menu.grid(row=2, column=1, pady=2, padx=5)
        ttk.Button(create_frame, text="Create User", command=self.create_user).grid(row=3, column=0, columnspan=2, pady=10)
        modify_frame = ttk.LabelFrame(user_mgmt_frame, text="Modify Selected User", padding="10")
        modify_frame.pack(fill=tk.X, pady=5)
        self.selected_user_label = ttk.Label(modify_frame, text="Selected: None", font=('Calibri', 10, 'italic'))
        self.selected_user_label.pack(pady=5)
        ttk.Label(modify_frame, text="New Password:").pack(anchor=tk.W, padx=5)
        self.reset_pass_entry = ttk.Entry(modify_frame, show="*")
        self.reset_pass_entry.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Button(modify_frame, text="Reset Password", command=self.reset_password).pack(fill=tk.X, padx=5)
        ttk.Label(modify_frame, text="New Role:").pack(anchor=tk.W, padx=5, pady=(10, 0))
        self.update_role_var = tk.StringVar()
        self.update_role_menu = ttk.Combobox(modify_frame, textvariable=self.update_role_var, values=["view", "edit", "admin"], state="readonly")
        self.update_role_menu.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Button(modify_frame, text="Update Role", command=self.update_role).pack(fill=tk.X, padx=5)
        self.load_users()

    def populate_dropdown_admin_tab(self):
        
        def create_management_frame(parent, title, api_url, data_map):
            frame = ttk.LabelFrame(parent, text=title, padding="10")
            frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            list_frame = ttk.Frame(frame)
            list_frame.pack(fill=tk.BOTH, expand=True)
            
            listbox = tk.Listbox(list_frame, height=15)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=listbox.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            listbox.config(yscrollcommand=scrollbar.set)
            
            for name in data_map.keys():
                listbox.insert(tk.END, name)
            
            entry_var = tk.StringVar()
            entry = ttk.Entry(frame, textvariable=entry_var)
            entry.pack(fill=tk.X, pady=5)
            
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X)
            
            def on_select(event):
                try:
                    selected_name = listbox.get(listbox.curselection())
                    entry_var.set(selected_name)
                except tk.TclError:
                    pass
            
            listbox.bind("<<ListboxSelect>>", on_select)

            def add_item():
                name = entry_var.get()
                if not name: return
                try:
                    response = requests.post(api_url, json={"name": name}, headers=self.auth_headers)
                    response.raise_for_status()
                    new_item = response.json()
                    data_map[new_item['name']] = new_item['id']
                    listbox.insert(tk.END, new_item['name'])
                    self.update_asset_comboboxes()
                    entry_var.set("")
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Could not add item: {e.response.text}")

            def update_item():
                name = entry_var.get()
                try:
                    selected_name = listbox.get(listbox.curselection())
                    item_id = data_map[selected_name]
                except (tk.TclError, KeyError):
                    return messagebox.showwarning("Warning", "Please select an item from the list to update.")
                
                if not name: return
                try:
                    response = requests.put(f"{api_url}/{item_id}", json={"name": name}, headers=self.auth_headers)
                    response.raise_for_status()
                    updated_item = response.json()
                    
                    del data_map[selected_name]
                    data_map[updated_item['name']] = updated_item['id']
                    listbox.delete(listbox.curselection())
                    listbox.insert(tk.END, updated_item['name'])
                    self.update_asset_comboboxes()
                    entry_var.set("")
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Could not update item: {e.response.text}")

            def delete_item():
                try:
                    selected_name = listbox.get(listbox.curselection())
                    item_id = data_map[selected_name]
                except (tk.TclError, KeyError):
                    return messagebox.showwarning("Warning", "Please select an item from the list to delete.")

                if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{selected_name}'?"):
                    return
                
                try:
                    response = requests.delete(f"{api_url}/{item_id}", headers=self.auth_headers)
                    response.raise_for_status()
                    
                    del data_map[selected_name]
                    listbox.delete(listbox.curselection())
                    self.update_asset_comboboxes()
                    entry_var.set("")
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Could not delete item: {e.response.text}")

            ttk.Button(button_frame, text="Add", command=add_item).pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(button_frame, text="Update", command=update_item).pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(button_frame, text="Delete", command=delete_item, style="Danger.TButton").pack(side=tk.LEFT, fill=tk.X, expand=True)

        create_management_frame(self.dropdown_admin_tab, "Categories", API_CATEGORIES_URL, self.category_map)
        create_management_frame(self.dropdown_admin_tab, "Locations", API_LOCATIONS_URL, self.location_map)
        create_management_frame(self.dropdown_admin_tab, "Departments", API_DEPARTMENTS_URL, self.department_map)

    def populate_app_custom_tab(self):
        frame = ttk.LabelFrame(self.app_custom_tab, text="Display Settings", padding="10")
        frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(frame, text="Resolution:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.resolution_var = tk.StringVar(value="1400x700")
        resolution_menu = ttk.Combobox(frame, textvariable=self.resolution_var, values=["1200x600", "1400x700", "1600x900", "Fullscreen"])
        resolution_menu.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Theme:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.theme_var = tk.StringVar(value="Default")
        theme_menu = ttk.Combobox(frame, textvariable=self.theme_var, values=["Default", "Dark Mode (coming soon)"], state="readonly")
        theme_menu.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.app_custom_tab, text="Save Display Settings", command=self.save_app_settings).pack(pady=20, anchor=tk.W, padx=10)

    def populate_server_settings_tab(self):
        frame = ttk.LabelFrame(self.server_settings_tab, text="Connection Settings", padding="10")
        frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(frame, text="Server URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_url_var = tk.StringVar(value=API_DOMAIN)
        server_url_entry = ttk.Entry(frame, textvariable=self.server_url_var, width=50)
        server_url_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.server_settings_tab, text="Save Connection Settings", command=self.save_server_settings).pack(pady=20, anchor=tk.W, padx=10)
        ttk.Label(self.server_settings_tab, text="NOTE: Application must be restarted for connection settings to take effect.", font=('Calibri', 9, 'italic')).pack(pady=5, anchor=tk.W, padx=10)

    def save_app_settings(self):
        resolution = self.resolution_var.get()
        theme = self.theme_var.get()
        try:
            if resolution == "Fullscreen":
                self.root.attributes('-fullscreen', True)
            else:
                self.root.attributes('-fullscreen', False)
                self.root.geometry(resolution)
            messagebox.showinfo("Settings", f"Display settings applied.\nResolution: {resolution}\nTheme: {theme}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not apply settings: {e}")

    def save_server_settings(self):
        url = self.server_url_var.get()
        messagebox.showwarning("Settings Saved", f"Server URL saved: {url}\n\nPlease restart the application for changes to take effect.")

    def load_all_dropdown_data(self):
        try:
            cat_res = requests.get(API_CATEGORIES_URL, headers=self.auth_headers)
            cat_res.raise_for_status()
            self.category_map = {item['name']: item['id'] for item in cat_res.json()}

            loc_res = requests.get(API_LOCATIONS_URL, headers=self.auth_headers)
            loc_res.raise_for_status()
            self.location_map = {item['name']: item['id'] for item in loc_res.json()}

            dep_res = requests.get(API_DEPARTMENTS_URL, headers=self.auth_headers)
            dep_res.raise_for_status()
            self.department_map = {item['name']: item['id'] for item in dep_res.json()}
            
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not load dropdown data. Please restart. Error: {e}")
            
    def update_asset_comboboxes(self):
        """Updates the dropdowns on the asset tab (form AND filters) with new values."""
        
        category_values = list(self.category_map.keys())
        location_values = list(self.location_map.keys())
        department_values = list(self.department_map.keys())
        
        self.asset_category_combo['values'] = category_values
        self.asset_location_combo['values'] = location_values
        self.asset_department_combo['values'] = department_values
        
        if hasattr(self, 'filter_entries'):
            if 'category' in self.filter_entries:
                self.filter_entries['category']['values'] = category_values
            if 'location' in self.filter_entries:
                self.filter_entries['location']['values'] = location_values
            if 'department' in self.filter_entries:
                self.filter_entries['department']['values'] = department_values

    # --- [MODIFIED] load_assets to populate all columns and filter by status ---
    def load_assets(self):
        try:
            for item in self.tree.get_children(): self.tree.delete(item)
            
            params = {}
            for key, widget in self.filter_entries.items():
                value = widget.get()
                if value:
                    # Handle special 'status_filter' case
                    if key == 'status_filter' and value != "All":
                        params['status'] = value.lower()
                    elif key != 'status_filter':
                        params[key] = value
            
            response = requests.get(API_ASSET_URL, params=params, headers=self.auth_headers)
            response.raise_for_status()
            
            for asset in response.json():
                cat_name = asset.get('category')['name'] if asset.get('category') else ""
                loc_name = asset.get('location')['name'] if asset.get('location') else ""
                dep_name = asset.get('department')['name'] if asset.get('department') else ""
                
                make = asset.get('make', '')
                model = asset.get('model', '')
                ip = asset.get('ip_address', '')
                value = asset.get('value_zar', '')
                status = asset.get('status', 'active') # <--- Get new status
                
                # Insert all values in the new correct order
                self.tree.insert("", tk.END, iid=asset["id"], values=[
                    asset["id"], status.title(), # <--- Insert status
                    asset.get("device_name", ""), asset.get("serial_number", ""),
                    cat_name, loc_name, dep_name, asset.get("allocated_user", ""),
                    make, model, ip, value
                ])
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not load assets: {e}")

    def add_asset(self):
        data = self.get_data_from_form()
        if not data: return
        try:
            response = requests.post(f"{API_ASSET_URL}/", json=data, headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", "Asset added successfully.")
            self.load_assets(); self.clear_form()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not add asset: {e.response.text}")

    def update_asset(self):
        selected_item = self.tree.focus()
        if not selected_item: return messagebox.showwarning("No Selection", "Please select an asset.")
        asset_id = self.tree.item(selected_item)["values"][0]
        data = self.get_data_from_form()
        if not data: return
        try:
            response = requests.put(f"{API_ASSET_URL}/{asset_id}", json=data, headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", "Asset updated successfully.")
            self.load_assets(); self.clear_form()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not update asset: {e.response.text}")

    def delete_asset(self):
        selected_item = self.tree.focus()
        if not selected_item: return messagebox.showwarning("No Selection", "Please select an asset.")
        asset_id = self.tree.item(selected_item)["values"][0]
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete asset ID {asset_id}?"):
            return
        try:
            response = requests.delete(f"{API_ASSET_URL}/{asset_id}", headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", "Asset deleted successfully.")
            self.load_assets(); self.clear_form()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not delete asset: {e.response.text}")

    # --- [NEW] Method to set asset status ---
    def set_asset_status(self, new_status: str):
        selected_item = self.tree.focus()
        if not selected_item: return messagebox.showwarning("No Selection", "Please select an asset.")
        asset_id = self.tree.item(selected_item)["values"][0]
        
        action = "Decommission" if new_status == "decommissioned" else "Reinstate"
        if not messagebox.askyesno(f"Confirm {action}", f"Are you sure you want to {action.lower()} asset ID {asset_id}?"):
            return
            
        try:
            response = requests.put(
                f"{API_ASSET_URL}/{asset_id}/status", 
                json={"status": new_status}, 
                headers=self.auth_headers
            )
            response.raise_for_status()
            messagebox.showinfo("Success", f"Asset {asset_id} successfully {action.lower()}d.")
            self.load_assets()
            self.clear_form()
        except requests.exceptions.RequestException as e:
            error_detail = e.response.json().get('detail', 'Unknown error') if e.response else str(e)
            messagebox.showerror("API Error", f"Could not {action.lower()} asset: {error_detail}")
    
    def load_users(self):
        try:
            for item in self.user_tree.get_children(): self.user_tree.delete(item)
            response = requests.get(API_USERS_URL, headers=self.auth_headers)
            response.raise_for_status()
            for user in response.json():
                self.user_tree.insert("", tk.END, iid=user["id"], values=(user["id"], user["username"], user["role"]))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not load users: {e.response.text}")

    def create_user(self):
        data = {"username": self.create_user_entry.get(), "password": self.create_pass_entry.get(), "role": self.create_role_var.get()}
        if not data["username"] or not data["password"]: return messagebox.showwarning("Missing Data", "Username and Password are required.")
        try:
            response = requests.post(f"{API_USERS_URL}/", json=data, headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", f"User '{data['username']}' created.")
            self.load_users()
            self.create_user_entry.delete(0, tk.END); self.create_pass_entry.delete(0, tk.END)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not create user: {e.response.text}")

    def reset_password(self):
        selected_item = self.user_tree.focus()
        if not selected_item: return messagebox.showwarning("No Selection", "Please select a user.")
        user_id = self.user_tree.item(selected_item)["values"][0]
        new_password = self.reset_pass_entry.get()
        if not new_password: return messagebox.showwarning("Missing Data", "New Password is required.")
        try:
            response = requests.put(f"{API_USERS_URL}/{user_id}/reset-password", json={"password": new_password}, headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", "Password reset successfully.")
            self.reset_pass_entry.delete(0, tk.END)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not reset password: {e.response.text}")

    def update_role(self):
        selected_item = self.user_tree.focus()
        if not selected_item: return messagebox.showwarning("No Selection", "Please select a user.")
        user_id = self.user_tree.item(selected_item)["values"][0]
        new_role = self.update_role_var.get()
        if not new_role: return messagebox.showwarning("Missing Data", "New Role is required.")
        try:
            response = requests.put(f"{API_USERS_URL}/{user_id}/role", json={"role": new_role}, headers=self.auth_headers)
            response.raise_for_status()
            messagebox.showinfo("Success", "Role updated successfully.")
            self.update_role_var.set(""); self.load_users()
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not update role: {e.response.text}")

    def on_user_select(self, event):
        selected_item = self.user_tree.focus()
        if not selected_item: return
        user_data = self.user_tree.item(selected_item)["values"]
        self.selected_user_label.config(text=f"Selected: {user_data[1]} (ID: {user_data[0]})")
        self.update_role_var.set(user_data[2])

    def get_data_from_form(self):
        data = {
            "serial_number": self.form_fields["Serial Number"].get(),
            "device_name": self.form_fields["Device Name"].get(),
            "allocated_user": self.form_fields["Allocated User"].get() or None,
            "ip_address": self.form_fields["IP Address"].get() or None,
            "make": self.form_fields["Make"].get(),
            "model": self.form_fields["Model"].get(),
            "value_zar": None,
            "category_id": self.category_map.get(self.asset_category_var.get()),
            "location_id": self.location_map.get(self.asset_location_var.get()),
            "department_id": self.department_map.get(self.asset_department_var.get())
        }
        
        if not all([data["serial_number"], data["device_name"], data["make"], data["model"]]):
            messagebox.showwarning("Missing Data", "Serial Number, Device Name, Make, and Model are required.")
            return None
        try:
            value_str = self.form_fields["Value (ZAR)"].get()
            if value_str: data["value_zar"] = float(value_str)
        except ValueError:
            messagebox.showwarning("Invalid Data", "Value (ZAR) must be a number.")
            return None
        return data

    def clear_form(self):
        for entry in self.form_fields.values(): entry.delete(0, tk.END)
        self.asset_category_var.set("")
        self.asset_location_var.set("")
        self.asset_department_var.set("")
        if self.tree.focus(): self.tree.selection_remove(self.tree.focus())

    def on_asset_select(self, event):
        selected_item = self.tree.focus()
        if not selected_item: return
        asset_id = self.tree.item(selected_item)["values"][0]
        try:
            response = requests.get(f"{API_ASSET_URL}/{asset_id}", headers=self.auth_headers)
            response.raise_for_status()
            asset = response.json()
            
            self.clear_form()
            
            all_text_fields = [
                "Serial Number", "Device Name", "Allocated User", "IP Address",
                "Make", "Model", "Value (ZAR)"
            ]
            key_map = {
                "Serial Number": "serial_number", "Device Name": "device_name",
                "Allocated User": "allocated_user", "IP Address": "ip_address",
                "Make": "make", "Model": "model", "Value (ZAR)": "value_zar"
            }
            
            for field in all_text_fields:
                key = key_map[field]
                self.form_fields[field].insert(0, str(asset.get(key, "")))
            
            if asset.get('category'):
                self.asset_category_var.set(asset['category']['name'])
            if asset.get('location'):
                self.asset_location_var.set(asset['location']['name'])
            if asset.get('department'):
                self.asset_department_var.set(asset['department']['name'])
                
        except requests.exceptions.RequestException as e:
            messagebox.showerror("API Error", f"Could not fetch asset details: {e}")

    def clear_filters(self):
        for key, widget in self.filter_entries.items():
            if isinstance(widget, ttk.Combobox):
                # Reset status filter to 'Active', others to ""
                if key == 'status_filter':
                    widget.set("Active")
                else:
                    widget.set("")
            else:
                widget.delete(0, tk.END)
        self.load_assets()

# --- Run the Application (Unchanged) ---
if __name__ == "__main__":
    login_root = tk.Tk()
    login_app = LoginWindow(login_root)
    login_root.mainloop()
    
    if login_app.login_data:
        main_root = tk.Tk()
        app = ByteBoltApp(
            main_root, 
            token=login_app.login_data['token'], 
            user=login_app.login_data['user']
        )
        main_root.mainloop()