import tkinter as tk
from tkinter import messagebox, ttk

from crackPassword import SIMULATION_LIMIT, simulate_bruteforce
from generatePassword import calculate_password_strength, generate_password


class ScrollablePage(tk.Frame):
    def __init__(self, parent, bg):
        super().__init__(parent, bg=bg)
        self.bg = bg

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.canvas, bg=bg)
        self.window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")

        self.content.bind("<Configure>", self._on_content_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        for widget in (self, self.canvas, self.content):
            widget.bind("<MouseWheel>", self._on_mousewheel)
            widget.bind("<Button-4>", self._on_mousewheel)
            widget.bind("<Button-5>", self._on_mousewheel)

    def _on_content_configure(self, _event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _on_mousewheel(self, event):
        if getattr(event, "delta", 0):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        elif getattr(event, "num", None) == 4:
            self.canvas.yview_scroll(-1, "units")
        elif getattr(event, "num", None) == 5:
            self.canvas.yview_scroll(1, "units")


class PasswordSecurityAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.colors = {
            "bg": "#07121d",
            "hero": "#0d2438",
            "hero_alt": "#173652",
            "card": "#f6fbff",
            "card_alt": "#e8f0f7",
            "ink": "#17324b",
            "muted": "#607c97",
            "line": "#d3e0eb",
            "white": "#f8fbff",
            "teal": "#29c4a5",
            "gold": "#f1b64c",
            "rose": "#e56b7c",
        }

        self.title("Password Security Analyzer")
        self.geometry("1000x680")
        self.minsize(880, 600)
        self.configure(bg=self.colors["bg"])

        self.length_var = tk.IntVar(value=12)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)

        self.password_var = tk.StringVar()
        self.generated_password_var = tk.StringVar()
        self.rating_var = tk.StringVar(value="Weak")
        self.entropy_var = tk.StringVar(value="0.00 bits")
        self.attempts_var = tk.StringVar(value="Pending")
        self.crack_time_var = tk.StringVar(value="Run simulation")
        self.mode_var = tk.StringVar(value="Analysis only")
        self.complexity_var = tk.StringVar(value="O(n^k)")
        self.generator_note_var = tk.StringVar(
            value="Choose password settings and generate a strong password."
        )
        self.analyzer_note_var = tk.StringVar(
            value="Use Analyze for strength and Simulate Brute Force for short/simple passwords."
        )
        self.attempts_note_var = tk.StringVar(
            value="Exact attempt counts appear only when the password is short enough for safe brute-force simulation."
        )

        self._build_styles()
        self._build_ui()
        self._set_generator_panel(
            [
                "Use at least 12 characters.",
                "Enable uppercase, lowercase, digits, and symbols for stronger passwords.",
            ]
        )
        self._set_analyzer_panel(
            [
                "Enter a password and click Analyze Password to calculate entropy and strength.",
                "Exact brute-force is intentionally limited to small search spaces so the demo remains responsive.",
            ]
        )
        self._set_recommendations(
            [
                "Use longer passwords to increase the search space dramatically.",
                "Mix multiple character types to raise entropy.",
                "Avoid short or predictable passwords if brute-force resistance matters.",
            ]
        )
        self._draw_strength_meter(0, self.colors["rose"])

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Primary.TButton", font=("Helvetica", 10, "bold"), padding=9)
        style.configure("Secondary.TButton", font=("Helvetica", 10), padding=8)
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", font=("Helvetica", 10, "bold"), padding=(16, 9))

    def _build_ui(self):
        root = tk.Frame(self, bg=self.colors["bg"])
        root.pack(fill="both", expand=True, padx=12, pady=12)

        hero = tk.Frame(
            root,
            bg=self.colors["hero"],
            highlightthickness=1,
            highlightbackground="#244a67",
            padx=16,
            pady=14,
        )
        hero.pack(fill="x", pady=(0, 10))

        tk.Label(
            hero,
            text="Password Security Analyzer",
            bg=self.colors["hero"],
            fg=self.colors["white"],
            font=("Helvetica", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            hero,
            text="Generate secure passwords, measure entropy, and demonstrate brute-force complexity.",
            bg=self.colors["hero"],
            fg="#a9c2da",
            font=("Helvetica", 10),
        ).pack(anchor="w", pady=(6, 10))

        stat_row = tk.Frame(hero, bg=self.colors["hero"])
        stat_row.pack(fill="x")
        self._hero_stat(stat_row, "Strength", self.rating_var, 0, 0)
        self._hero_stat(stat_row, "Entropy", self.entropy_var, 0, 1)
        self._hero_stat(stat_row, "Crack Time", self.crack_time_var, 0, 2)
        self._hero_stat(stat_row, "Complexity", self.complexity_var, 0, 3)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.main_page = ScrollablePage(notebook, self.colors["bg"])
        self.recommendations_page = ScrollablePage(notebook, self.colors["bg"])
        notebook.add(self.main_page, text="Main")
        notebook.add(self.recommendations_page, text="Recommendations")

        self._build_main_page(self.main_page.content)
        self._build_recommendations_page(self.recommendations_page.content)

    def _build_main_page(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        generator = self._card(parent)
        generator.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))
        self._build_generator_card(generator)

        analyzer = self._card(parent)
        analyzer.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=(0, 8))
        self._build_analyzer_card(analyzer)

    def _build_recommendations_page(self, parent):
        card = self._card(parent)
        card.pack(fill="both", expand=True)

        self._card_header(
            card,
            "Security Recommendation Panel",
            "Project guidance and improvement suggestions for the password being tested.",
        )

        intro = self._soft_box(card)
        intro.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 9),
            wraplength=860,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))

        self.recommendations_text = tk.Text(
            card,
            wrap="word",
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            relief="flat",
            font=("Helvetica", 11),
            padx=16,
            pady=16,
            height=18,
        )
        self.recommendations_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.recommendations_text.configure(state="disabled")

    def _hero_stat(self, parent, label, variable, row, column):
        parent.grid_columnconfigure(column, weight=1)
        card = tk.Frame(
            parent,
            bg=self.colors["hero_alt"],
            highlightthickness=1,
            highlightbackground="#2c5678",
            padx=10,
            pady=8,
        )
        card.grid(row=row, column=column, sticky="nsew", padx=4)
        tk.Label(
            card,
            text=label.upper(),
            bg=self.colors["hero_alt"],
            fg="#9fc0df",
            font=("Helvetica", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            card,
            textvariable=variable,
            bg=self.colors["hero_alt"],
            fg=self.colors["white"],
            font=("Helvetica", 12, "bold"),
            justify="left",
            wraplength=150,
        ).pack(anchor="w", pady=(6, 0))

    def _card(self, parent):
        return tk.Frame(
            parent,
            bg=self.colors["card"],
            highlightthickness=1,
            highlightbackground=self.colors["line"],
        )

    def _card_header(self, parent, title, description):
        tk.Label(
            parent,
            text=title,
            bg=self.colors["card"],
            fg=self.colors["ink"],
            font=("Helvetica", 14, "bold"),
        ).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(
            parent,
            text=description,
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Helvetica", 9),
            justify="left",
            wraplength=430,
        ).pack(anchor="w", padx=16, pady=(0, 12))

    def _soft_box(self, parent):
        return tk.Frame(
            parent,
            bg=self.colors["card_alt"],
            highlightthickness=1,
            highlightbackground=self.colors["line"],
            padx=10,
            pady=10,
        )

    def _toggle(self, parent, text, variable, row, column):
        parent.grid_columnconfigure(column, weight=1)
        box = self._soft_box(parent)
        box.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        ttk.Checkbutton(box, text=text, variable=variable).pack(anchor="w")

    def _metric(self, parent, label, variable, row, column):
        parent.grid_columnconfigure(column, weight=1)
        box = self._soft_box(parent)
        box.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        tk.Label(
            box,
            text=label.upper(),
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            box,
            textvariable=variable,
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            font=("Helvetica", 10, "bold"),
            justify="left",
            wraplength=170,
        ).pack(anchor="w", pady=(6, 0))

    def _build_generator_card(self, parent):
        self._card_header(
            parent,
            "Password Generator",
            "Create a strong password with configurable rules.",
        )

        controls = self._soft_box(parent)
        controls.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(
            controls,
            text="Password Length",
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 10),
        ).pack(side="left")
        ttk.Spinbox(
            controls, from_=4, to=32, textvariable=self.length_var, width=8
        ).pack(side="right")

        toggle_grid = tk.Frame(parent, bg=self.colors["card"])
        toggle_grid.pack(fill="x", padx=16)
        self._toggle(toggle_grid, "Lowercase", self.lowercase_var, 0, 0)
        self._toggle(toggle_grid, "Uppercase", self.uppercase_var, 0, 1)
        self._toggle(toggle_grid, "Digits", self.digits_var, 1, 0)
        self._toggle(toggle_grid, "Symbols", self.symbols_var, 1, 1)

        button_row = tk.Frame(parent, bg=self.colors["card"])
        button_row.pack(fill="x", padx=16, pady=(12, 10))
        ttk.Button(
            button_row,
            text="Generate Password",
            style="Primary.TButton",
            command=self.generate_password_ui,
        ).pack(side="left")
        ttk.Button(
            button_row,
            text="Use In Analyzer",
            style="Secondary.TButton",
            command=self.use_generated_password,
        ).pack(side="left", padx=8)

        password_box = tk.Frame(
            parent,
            bg="#11263d",
            highlightthickness=1,
            highlightbackground="#29506f",
            padx=12,
            pady=12,
        )
        password_box.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(
            password_box,
            text="Generated Password",
            bg="#11263d",
            fg="#a5c2dd",
            font=("Helvetica", 10),
        ).pack(anchor="w")
        tk.Entry(
            password_box,
            textvariable=self.generated_password_var,
            font=("Courier", 13, "bold"),
            relief="flat",
            bg="#11263d",
            fg=self.colors["white"],
            insertbackground=self.colors["white"],
            bd=0,
        ).pack(fill="x", pady=(10, 0), ipady=2)

        generator_panel = self._soft_box(parent)
        generator_panel.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        tk.Label(
            generator_panel,
            text="Generator Guidance",
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w")
        tk.Label(
            generator_panel,
            textvariable=self.generator_note_var,
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 9),
            justify="left",
            wraplength=380,
        ).pack(anchor="w", pady=(6, 0))
        self.generator_text = tk.Text(
            generator_panel,
            height=6,
            wrap="word",
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            relief="flat",
            font=("Helvetica", 10),
            padx=0,
            pady=6,
        )
        self.generator_text.pack(fill="both", expand=True)
        self.generator_text.configure(state="disabled")

    def _build_analyzer_card(self, parent):
        self._card_header(
            parent,
            "Password Analyzer",
            "Measure strength, attempts made, and estimated brute-force crack time.",
        )

        input_box = self._soft_box(parent)
        input_box.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(
            input_box,
            text="Password To Test",
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 10),
        ).pack(anchor="w")
        tk.Entry(
            input_box,
            textvariable=self.password_var,
            font=("Courier", 13),
            relief="flat",
            bg="#ffffff",
            fg=self.colors["ink"],
            insertbackground=self.colors["ink"],
            bd=0,
        ).pack(fill="x", pady=(10, 0), ipady=8)

        control_row = tk.Frame(parent, bg=self.colors["card"])
        control_row.pack(fill="x", padx=16, pady=(0, 10))
        ttk.Button(
            control_row,
            text="Analyze Password",
            style="Primary.TButton",
            command=self.analyze_password,
        ).pack(side="left")
        ttk.Button(
            control_row,
            text="Simulate Brute Force",
            style="Secondary.TButton",
            command=self.run_simulation,
        ).pack(side="left", padx=8)

        rating_row = tk.Frame(parent, bg=self.colors["card"])
        rating_row.pack(fill="x", padx=16)
        tk.Label(
            rating_row,
            text="Strength Rating",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Helvetica", 10),
        ).pack(side="left")
        self.rating_badge = tk.Label(
            rating_row,
            textvariable=self.rating_var,
            bg="#ffe4e8",
            fg="#a43f4e",
            font=("Helvetica", 10, "bold"),
            padx=10,
            pady=4,
        )
        self.rating_badge.pack(side="right")

        self.strength_canvas = tk.Canvas(
            parent,
            height=26,
            bg=self.colors["card"],
            highlightthickness=0,
            bd=0,
        )
        self.strength_canvas.pack(fill="x", padx=16, pady=(8, 10))

        metrics = tk.Frame(parent, bg=self.colors["card"])
        metrics.pack(fill="x", padx=16, pady=(0, 10))
        self._metric(metrics, "Entropy", self.entropy_var, 0, 0)
        self._metric(metrics, "Attempts Made", self.attempts_var, 0, 1)
        self._metric(metrics, "Estimated Crack Time", self.crack_time_var, 1, 0)
        self._metric(metrics, "Simulation Mode", self.mode_var, 1, 1)

        tk.Label(
            parent,
            textvariable=self.attempts_note_var,
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Helvetica", 9),
            justify="left",
            wraplength=380,
        ).pack(anchor="w", padx=16, pady=(2, 10))

        analyzer_panel = self._soft_box(parent)
        analyzer_panel.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        tk.Label(
            analyzer_panel,
            text="Analysis Summary",
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w")
        tk.Label(
            analyzer_panel,
            textvariable=self.analyzer_note_var,
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            font=("Helvetica", 9),
            justify="left",
            wraplength=380,
        ).pack(anchor="w", pady=(6, 0))
        self.analyzer_text = tk.Text(
            analyzer_panel,
            height=8,
            wrap="word",
            bg=self.colors["card_alt"],
            fg=self.colors["ink"],
            relief="flat",
            font=("Helvetica", 10),
            padx=0,
            pady=6,
        )
        self.analyzer_text.pack(fill="both", expand=True)
        self.analyzer_text.configure(state="disabled")

    def generate_password_ui(self):
        try:
            password = generate_password(
                length=self.length_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get(),
            )
        except ValueError as error:
            messagebox.showerror("Generation Error", str(error))
            return

        self.generated_password_var.set(password)
        self.password_var.set(password)
        self.generator_note_var.set(
            "Password generated successfully and loaded into the analyzer."
        )
        self._set_generator_panel(
            [
                "Greedy selection ensures every enabled character type appears at least once.",
                "Longer passwords increase search space much faster than adding only one more character type.",
                "For exact brute-force demos, test short inputs such as a1, abc, or zzzz.",
            ]
        )
        self.analyze_password()

    def use_generated_password(self):
        password = self.generated_password_var.get()
        if not password:
            messagebox.showinfo("No Password", "Generate a password first.")
            return
        self.password_var.set(password)
        self.analyze_password()

    def analyze_password(self):
        password = self.password_var.get()
        metrics = calculate_password_strength(password)

        self.rating_var.set(metrics["strength"])
        self.entropy_var.set(f"{metrics['entropy_bits']} bits")
        self.attempts_var.set("Pending")
        self.crack_time_var.set("Run simulation")
        self.mode_var.set("Analysis only")
        self.complexity_var.set("O(n^k)")
        self.attempts_note_var.set(
            "Exact attempt counts appear only when the password is short enough for safe brute-force simulation."
        )
        self.analyzer_note_var.set(
            "Strength analysis updated from entropy, length, and character variety."
        )

        self._draw_strength_meter(
            metrics["score"], self._strength_color(metrics["strength"])
        )
        self._update_badge(metrics["strength"])

        analyzer_items = [
            f"Strength rating: {metrics['strength']}.",
            f"Entropy score: {metrics['entropy_bits']} bits based on a character pool of {metrics['pool_size']}.",
            "Brute-force complexity is O(n^k), where n is charset size and k is password length.",
            "Use Simulate Brute Force on short/simple passwords to get a real attempt count.",
        ] + metrics["recommendations"]
        self._set_analyzer_panel(analyzer_items)
        self._set_recommendations(metrics["recommendations"])

    def run_simulation(self):
        password = self.password_var.get()
        if not password:
            messagebox.showinfo("Missing Password", "Enter a password before simulating.")
            return

        metrics = calculate_password_strength(password)
        result = simulate_bruteforce(password, max_combinations=SIMULATION_LIMIT)

        self.rating_var.set(metrics["strength"])
        self.entropy_var.set(f"{metrics['entropy_bits']} bits")
        self.crack_time_var.set(result["estimated"]["formatted_time"])
        self.mode_var.set(result["mode"].replace("_", " ").title())
        self.complexity_var.set(result["estimated"]["complexity"])
        self.analyzer_note_var.set(result["message"])

        if result["mode"] == "simulated":
            self.attempts_var.set(f"{result['attempts']:,}")
            self.attempts_note_var.set(
                "Exact attempt count shown because the full brute-force simulation was safely completed."
            )
        else:
            self.attempts_var.set("Not simulated")
            self.attempts_note_var.set(
                "No real attempt count is available because the app switched to estimate mode for a larger search space."
            )

        self._draw_strength_meter(
            metrics["score"], self._strength_color(metrics["strength"])
        )
        self._update_badge(metrics["strength"])

        summary = [
            f"Strength rating: {metrics['strength']}.",
            f"Estimated crack time: {result['estimated']['formatted_time']}.",
            f"Brute-force complexity: {result['estimated']['complexity']}.",
        ]
        if result["mode"] == "simulated":
            summary.append(
                f"Exact simulation completed in {result['attempts']:,} attempts."
            )
        else:
            summary.append(
                "Exact brute-force was skipped because the search space is too large or the password is above the safe simulation limit."
            )

        self._set_analyzer_panel(summary + metrics["recommendations"])
        self._set_recommendations(summary + metrics["recommendations"])

    def _set_generator_panel(self, items):
        self.generator_text.configure(state="normal")
        self.generator_text.delete("1.0", tk.END)
        for item in items:
            self.generator_text.insert(tk.END, f"• {item}\n\n")
        self.generator_text.configure(state="disabled")

    def _set_analyzer_panel(self, items):
        self.analyzer_text.configure(state="normal")
        self.analyzer_text.delete("1.0", tk.END)
        for item in items:
            self.analyzer_text.insert(tk.END, f"• {item}\n\n")
        self.analyzer_text.configure(state="disabled")

    def _set_recommendations(self, items):
        self.recommendations_text.configure(state="normal")
        self.recommendations_text.delete("1.0", tk.END)
        for item in items:
            self.recommendations_text.insert(tk.END, f"• {item}\n\n")
        self.recommendations_text.configure(state="disabled")

    def _draw_strength_meter(self, score, color):
        self.strength_canvas.delete("all")
        width = max(self.strength_canvas.winfo_width(), 400)
        height = 24
        self._rounded_rect(
            self.strength_canvas, 0, 0, width, height, 12, fill="#dbe5ee", outline=""
        )
        fill_width = max(0, min(width, int(width * (score / 100))))
        if fill_width:
            self._rounded_rect(
                self.strength_canvas,
                0,
                0,
                max(fill_width, 12),
                height,
                12,
                fill=color,
                outline="",
            )
        self.strength_canvas.create_text(
            width / 2,
            height / 2,
            text=f"{score}/100",
            fill=self.colors["ink"],
            font=("Helvetica", 10, "bold"),
        )

    def _update_badge(self, strength):
        if strength == "Strong":
            bg, fg = "#ddf7ef", "#1f8061"
        elif strength == "Medium":
            bg, fg = "#fff1d9", "#9d6a15"
        else:
            bg, fg = "#ffe5ea", "#a43f4e"
        self.rating_badge.configure(bg=bg, fg=fg)

    def _rounded_rect(self, canvas, x1, y1, x2, y2, radius, **kwargs):
        radius = min(radius, (x2 - x1) / 2, (y2 - y1) / 2)
        points = [
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        ]
        return canvas.create_polygon(points, smooth=True, splinesteps=36, **kwargs)

    def _strength_color(self, strength):
        if strength == "Strong":
            return self.colors["teal"]
        if strength == "Medium":
            return self.colors["gold"]
        return self.colors["rose"]


if __name__ == "__main__":
    app = PasswordSecurityAnalyzer()
    app.mainloop()
