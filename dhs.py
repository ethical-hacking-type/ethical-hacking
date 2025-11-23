from flask import Flask, render_template_string, redirect, url_for

app = Flask(__name__)

# --- DATA (Moved from JS to Python) ---
# This acts as our database for the application.
CURRICULUM = [
    {
        'id': 'intro',
        'title': 'Introduction & Ethics',
        'icon': 'shield',
        'color': 'text-blue-400',
        'content': {
            'heading': "Foundations of Ethical Hacking",
            'description': "Ethical hacking involves an authorized attempt to gain unauthorized access to a computer system, application, or data. Carrying out an ethical hack involves duplicating strategies and actions of malicious attackers.",
            'sections': [
                {
                    'title': "The CIA Triad",
                    'text': "The core of information security. All security controls act to protect one or more of these principles.",
                    'points': [
                        {'label': "Confidentiality", 'desc': "Protecting data from unauthorized access."},
                        {'label': "Integrity", 'desc': "Ensuring data is not altered or tampered with."},
                        {'label': "Availability", 'desc': "Ensuring systems are up and running for authorized users."}
                    ]
                },
                {
                    'title': "Types of Hackers",
                    'text': "Understanding the ecosystem.",
                    'points': [
                        {'label': "White Hat", 'desc': "Ethical hackers. Authorized. Improving security."},
                        {'label': "Black Hat", 'desc': "Malicious hackers. Unauthorized. Personal gain or damage."},
                        {'label': "Grey Hat", 'desc': "Somewhere in between. Often illegal but not necessarily malicious."}
                    ]
                },
                {
                    'title': "Legal & Compliance",
                    'text': "CRITICAL: You must always have written permission before scanning or testing any system. Unauthorized scanning is illegal in most jurisdictions (CFAA in USA, Computer Misuse Act in UK).",
                    'isWarning': True
                }
            ]
        }
    },
    {
        'id': 'recon',
        'title': 'Reconnaissance',
        'icon': 'search',
        'color': 'text-green-400',
        'content': {
            'heading': "Phase 1: Reconnaissance",
            'description': "Also known as footprinting, this is the preparatory phase where an attacker gathers as much information as possible about the target network prior to launching an attack.",
            'sections': [
                {
                    'title': "Passive vs Active",
                    'text': "The difference lies in detection risk.",
                    'points': [
                        {'label': "Passive Recon", 'desc': "Gathering info without interacting directly with the target."},
                        {'label': "Active Recon", 'desc': "Direct interaction (e.g., Pinging, Nmap scans). Higher risk of detection."}
                    ]
                },
                {
                    'title': "OSINT Tools",
                    'tools': ["Maltego", "TheHarvester", "Shodan", "Google Dorks"]
                },
                {
                    'title': "Interactive Tool: Google Dorking",
                    'type': "dork_sim"
                }
            ]
        }
    },
    {
        'id': 'scanning',
        'title': 'Scanning & Enumeration',
        'icon': 'activity',
        'color': 'text-purple-400',
        'content': {
            'heading': "Phase 2: Scanning",
            'description': "Scanning involves taking the information discovered during reconnaissance and using it to examine the network.",
            'sections': [
                {
                    'title': "Scanning Types",
                    'text': "Identifying open doors (ports) on a server.",
                    'tools': ["Nmap (Network Mapper)", "Masscan", "RustScan", "Nessus"]
                },
                {
                    'title': "Simulation: Nmap Command Generator",
                    'type': "nmap_sim"
                }
            ]
        }
    },
    {
        'id': 'network',
        'title': 'Network Sniffing',
        'icon': 'wifi',
        'color': 'text-yellow-400',
        'content': {
            'heading': "Network Sniffing & MITM",
            'description': "Sniffing is the process of monitoring and capturing all the packets passing through a given network using a packet sniffer.",
            'sections': [
                {
                    'title': "Key Concepts",
                    'points': [
                        {'label': "Promiscuous Mode", 'desc': "NIC mode that passes all traffic to the CPU."},
                        {'label': "ARP Spoofing", 'desc': "Linking attacker's MAC with legitimate IP."}
                    ]
                },
                {
                    'title': "Tools of the Trade",
                    'tools': ["Wireshark", "Tcpdump", "Bettercap", "Ettercap"]
                }
            ]
        }
    },
    {
        'id': 'web',
        'title': 'Web App Hacking',
        'icon': 'globe',
        'color': 'text-pink-400',
        'content': {
            'heading': "Web Application Penetration Testing",
            'description': "Focuses on vulnerabilities within web applications, often leveraging the OWASP Top 10.",
            'sections': [
                {
                    'title': "OWASP Top 10 (Critical)",
                    'points': [
                        {'label': "Injection (SQLi)", 'desc': "Untrusted data sent to interpreter."},
                        {'label': "Broken Access Control", 'desc': "Users acting outside permissions."},
                        {'label': "XSS", 'desc': "Injecting malicious scripts into websites."}
                    ]
                },
                {
                    'title': "Tools",
                    'tools': ["Burp Suite", "OWASP ZAP", "SQLMap"]
                }
            ]
        }
    },
    {
        'id': 'passwords',
        'title': 'Cryptography',
        'icon': 'hash',
        'color': 'text-red-400',
        'content': {
            'heading': "Cracking & Encryption",
            'description': "Understanding how data is scrambled and how attackers reverse that process.",
            'sections': [
                {
                    'title': "Attack Types",
                    'points': [
                        {'label': "Brute Force", 'desc': "Trying every possible combination."},
                        {'label': "Dictionary Attack", 'desc': "Using a list of common words."},
                        {'label': "Rainbow Tables", 'desc': "Precomputed hash tables."}
                    ]
                },
                {
                    'title': "Interactive: Password Strength",
                    'type': "password_sim"
                }
            ]
        }
    },
    {
        'id': 'malware',
        'title': 'Malware Threats',
        'icon': 'alert-triangle',
        'color': 'text-orange-400',
        'content': {
            'heading': "Malicious Software",
            'description': "Software intentionally designed to cause damage to a computer, server, client, or computer network.",
            'sections': [
                {
                    'title': "Types",
                    'points': [
                        {'label': "Virus", 'desc': "Attaches to host and replicates."},
                        {'label': "Worm", 'desc': "Self-replicating network spreader."},
                        {'label': "Ransomware", 'desc': "Encrypts data and demands payment."}
                    ]
                }
            ]
        }
    }
]

# --- TEMPLATE ---
# We use Jinja2 syntax ({{ variable }}) to inject Python data into HTML.
# In a real app, this would be in a separate file like 'templates/index.html'.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ active_module.title }} | Ethical Hacking Academy</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
    
    <style>
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        .selection-green::selection { background-color: rgba(34, 197, 94, 0.3); color: #bbf7d0; }
    </style>
</head>
<body class="bg-black text-slate-300 font-sans h-screen flex overflow-hidden selection-green">

    <!-- Mobile Overlay -->
    <div id="mobile-overlay" class="fixed inset-0 bg-black/80 z-20 hidden backdrop-blur-sm" onclick="toggleMobileMenu()"></div>

    <!-- Sidebar -->
    <aside id="sidebar" class="fixed md:static inset-y-0 left-0 z-30 w-72 bg-slate-950 border-r border-slate-800 transform -translate-x-full md:translate-x-0 transition-transform duration-300 ease-in-out flex flex-col h-full">
        <div class="p-6 border-b border-slate-800">
            <div class="flex items-center gap-2 text-green-500 mb-1">
                <i data-lucide="terminal" class="w-6 h-6"></i>
                <span class="font-bold tracking-tight text-lg text-white">Ethical<span class="text-green-500">Hacking</span>101</span>
            </div>
            <p class="text-xs text-slate-500 font-mono pl-8">Educational Use</p>
        </div>

        <!-- Python Loop for Sidebar -->
        <div class="flex-1 overflow-y-auto py-4 px-3 space-y-1">
            {% for item in curriculum %}
                <a href="/module/{{ item.id }}" 
                   class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group 
                   {% if item.id == active_module.id %}
                        bg-slate-800 border-l-4 border-green-500 text-white shadow-[0_0_15px_rgba(34,197,94,0.15)]
                   {% else %}
                        text-slate-400 hover:bg-slate-800 hover:text-white
                   {% endif %}">
                    <div class="transition-colors {% if item.id == active_module.id %}{{ item.color }}{% else %}text-slate-500 group-hover:text-slate-300{% endif %}">
                        <i data-lucide="{{ item.icon }}" class="w-5 h-5"></i>
                    </div>
                    <span class="font-medium text-sm text-left">{{ item.title }}</span>
                    {% if item.id == active_module.id %}
                        <i data-lucide="chevron-right" class="w-4 h-4 ml-auto text-green-500"></i>
                    {% endif %}
                </a>
            {% endfor %}
        </div>

        <div class="p-4 border-t border-slate-800">
            <div class="bg-slate-900 rounded p-3 flex items-start gap-3">
                <i data-lucide="alert-triangle" class="w-5 h-5 text-yellow-500 shrink-0"></i>
                <p class="text-[10px] text-slate-400 leading-tight">
                    Disclaimer: The developer is not responsible for misuse of this information. Stay legal.
                </p>
            </div>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 flex flex-col h-full min-w-0 relative">
        <!-- Mobile Header -->
        <div class="md:hidden flex items-center justify-between p-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur z-10 sticky top-0">
            <span class="font-bold text-white">Module View</span>
            <button onclick="toggleMobileMenu()" class="p-2 text-slate-400 hover:text-white">
                <i data-lucide="menu" class="w-6 h-6"></i>
            </button>
        </div>

        <!-- Scrollable Content Area -->
        <div id="main-scroll" class="flex-1 overflow-y-auto bg-slate-950/50 p-4 md:p-8 lg:p-12 scroll-smooth">
            <div class="max-w-4xl mx-auto">
                <!-- Breadcrumbs -->
                <div class="flex items-center gap-2 text-xs font-mono text-slate-500 mb-6">
                    <span>root</span>
                    <span>/</span>
                    <span>academy</span>
                    <span>/</span>
                    <span class="text-green-500">{{ active_module.id }}</span>
                </div>

                <!-- Dynamic Content (Rendered by Python) -->
                <div class="fade-in">
                    <div class="border-b border-slate-800 pb-6 mb-8">
                        <div class="flex items-center gap-3 mb-2">
                            <span class="p-2 rounded-lg bg-slate-800 {{ active_module.color }}">
                                <i data-lucide="{{ active_module.icon }}" class="w-5 h-5"></i>
                            </span>
                            <span class="text-slate-400 uppercase tracking-wider text-xs font-bold">Module</span>
                        </div>
                        <h1 class="text-3xl md:text-4xl font-bold text-white mb-4">{{ active_module.content.heading }}</h1>
                        <p class="text-slate-400 text-lg leading-relaxed">{{ active_module.content.description }}</p>
                    </div>

                    <div class="space-y-12">
                        {% for section in active_module.content.sections %}
                        <div class="relative pl-6 border-l-2 border-slate-800 hover:border-slate-600 transition-colors">
                            <h2 class="text-xl font-bold text-slate-200 mb-3">{{ section.title }}</h2>

                            {% if section.isWarning %}
                                <div class="bg-red-900/20 border border-red-500/50 rounded-md p-4 flex items-start gap-3 my-4">
                                    <i data-lucide="alert-triangle" class="w-6 h-6 text-red-500 shrink-0 mt-0.5"></i>
                                    <div class="text-red-200 text-sm leading-relaxed">{{ section.text }}</div>
                                </div>
                            {% elif section.text %}
                                <p class="text-slate-400 mb-4">{{ section.text }}</p>
                            {% endif %}

                            {% if section.points %}
                                <ul class="space-y-3 mb-4">
                                    {% for pt in section.points %}
                                    <li class="flex gap-3 text-sm md:text-base">
                                        <div class="w-1.5 h-1.5 rounded-full bg-slate-500 mt-2 shrink-0"></div>
                                        <div>
                                            <span class="text-slate-200 font-medium">{{ pt.label }}:</span>
                                            <span class="text-slate-400 ml-1">{{ pt.desc }}</span>
                                        </div>
                                    </li>
                                    {% endfor %}
                                </ul>
                            {% endif %}

                            {% if section.tools %}
                                <div class="bg-slate-900/50 p-4 rounded-lg border border-slate-800">
                                    <h4 class="text-xs text-slate-500 uppercase tracking-widest font-bold mb-3">Recommended Tools</h4>
                                    <div class="flex flex-wrap gap-2">
                                        {% for tool in section.tools %}
                                            <span class="px-3 py-1 bg-slate-800 text-green-400 font-mono text-sm rounded border border-slate-700">{{ tool }}</span>
                                        {% endfor %}
                                    </div>
                                </div>
                            {% endif %}

                            <!-- Specific Simulators Logic -->
                            {% if section.type == 'nmap_sim' %}
                                <div class="bg-slate-900 p-4 rounded-lg border border-slate-700 space-y-4 mt-4">
                                    <h3 class="text-white font-semibold flex items-center gap-2"><i data-lucide="terminal" class="w-4 h-4"></i> Command Builder</h3>
                                    <div class="flex flex-col md:flex-row gap-4">
                                        <div class="flex-1">
                                            <label class="text-xs text-slate-400 block mb-1">Scan Type</label>
                                            <select id="nmap-flags" class="w-full bg-slate-800 text-white p-2 rounded border border-slate-600 focus:border-green-500 outline-none font-mono text-sm">
                                                <option value="-sS">-sS (Stealth SYN)</option>
                                                <option value="-sT">-sT (TCP Connect)</option>
                                                <option value="-sV">-sV (Version Det)</option>
                                                <option value="-A">-A (Aggressive)</option>
                                            </select>
                                        </div>
                                        <div class="flex-1">
                                            <label class="text-xs text-slate-400 block mb-1">Target IP</label>
                                            <input id="nmap-target" type="text" value="192.168.1.1" class="w-full bg-slate-800 text-white p-2 rounded border border-slate-600 focus:border-green-500 outline-none font-mono text-sm">
                                        </div>
                                        <div class="flex items-end">
                                            <button id="nmap-run-btn" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-mono text-sm transition-colors disabled:opacity-50">Run Scan</button>
                                        </div>
                                    </div>
                                    <div class="bg-black p-3 rounded font-mono text-xs md:text-sm text-green-500 h-48 overflow-y-auto border border-slate-800" id="nmap-console">
                                        <div class="opacity-50 select-none mb-2">$ nmap -sS 192.168.1.1</div>
                                        <span class="animate-pulse">_</span>
                                    </div>
                                </div>
                            {% endif %}

                            {% if section.type == 'dork_sim' %}
                                <div class="bg-slate-900 p-4 rounded-lg border border-slate-700 space-y-4 mt-4">
                                    <div class="flex gap-2 overflow-x-auto pb-2" id="dork-buttons">
                                        <button class="bg-slate-800 text-xs text-blue-300 px-3 py-1 rounded hover:bg-slate-700 whitespace-nowrap" data-val="site:target.com filetype:pdf">Public PDF Files</button>
                                        <button class="bg-slate-800 text-xs text-blue-300 px-3 py-1 rounded hover:bg-slate-700 whitespace-nowrap" data-val="site:target.com inurl:admin">Admin Panels</button>
                                        <button class="bg-slate-800 text-xs text-blue-300 px-3 py-1 rounded hover:bg-slate-700 whitespace-nowrap" data-val='intitle:"index of"'>Directory Listing</button>
                                    </div>
                                    <div class="relative">
                                        <input id="dork-input" type="text" value="site:example.com filetype:pdf" class="w-full pl-10 pr-4 py-3 bg-white text-slate-800 rounded-full border-2 border-transparent focus:border-blue-500 outline-none shadow-sm font-mono text-sm">
                                        <i data-lucide="search" class="absolute left-3 top-3.5 w-4 h-4 text-slate-400 z-10"></i>
                                    </div>
                                    <div class="text-xs text-slate-400">* In a real scenario, this would be entered into Google search engine.</div>
                                </div>
                            {% endif %}

                            {% if section.type == 'password_sim' %}
                                <div class="bg-slate-900 p-6 rounded-lg border border-slate-700 mt-4">
                                    <h3 class="text-white font-semibold mb-4">Password Entropy Checker</h3>
                                    <input id="pass-input" type="text" placeholder="Type a password..." class="w-full bg-slate-800 text-white p-3 rounded border border-slate-600 focus:border-purple-500 outline-none mb-4 font-mono">
                                    <div class="space-y-2">
                                        <div class="flex justify-between text-xs text-slate-400">
                                            <span id="pass-strength-text">Strength: Too Short</span>
                                            <span id="pass-time-text">Time to Crack: Instantly</span>
                                        </div>
                                        <div class="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                                            <div id="pass-bar" class="h-full transition-all duration-500 bg-red-500" style="width: 0%"></div>
                                        </div>
                                    </div>
                                </div>
                            {% endif %}

                        </div>
                        {% endfor %}
                    </div>
                </div>

                <!-- Footer -->
                <footer class="mt-20 pt-8 border-t border-slate-800 text-center text-slate-600 text-sm">
                    <p>&copy; 2023 Ethical Hacking Academy. Build Secure Systems.</p>
                    <div class="flex justify-center gap-4 mt-2">
                        <span class="cursor-pointer hover:text-slate-400">Privacy</span>
                        <span class="cursor-pointer hover:text-slate-400">Terms</span>
                        <span class="cursor-pointer hover:text-slate-400">Resources</span>
                    </div>
                </footer>
            </div>
        </div>
    </main>

    <!-- Client-Side Scripts (Simulators & Menu Toggle) -->
    <script>
        // Init Icons
        lucide.createIcons();

        // Mobile Menu Logic
        let isMobileMenuOpen = false;
        function toggleMobileMenu() {
            isMobileMenuOpen = !isMobileMenuOpen;
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('mobile-overlay');

            if (isMobileMenuOpen) {
                sidebar.classList.remove('-translate-x-full');
                overlay.classList.remove('hidden');
            } else {
                sidebar.classList.add('-translate-x-full');
                overlay.classList.add('hidden');
            }
        }

        // --- SIMULATOR LOGIC (Runs only if elements exist) ---

        // NMAP SIMULATOR
        const nmapBtn = document.getElementById('nmap-run-btn');
        if(nmapBtn) {
            nmapBtn.addEventListener('click', () => {
                const flags = document.getElementById('nmap-flags').value;
                const target = document.getElementById('nmap-target').value;
                const consoleDiv = document.getElementById('nmap-console');
                
                nmapBtn.disabled = true;
                nmapBtn.innerText = 'Scanning...';
                consoleDiv.innerHTML = `<div class="opacity-50 select-none mb-2">$ nmap ${flags} ${target}</div><span class="animate-pulse">...</span>`;

                setTimeout(() => {
                    let result = `Starting Nmap 7.92 at 2023-10-14 10:00 EST<br>`;
                    result += `Nmap scan report for ${target}<br>`;
                    result += `Host is up (0.0023s latency).<br>`;
                    result += `Not shown: 997 closed tcp ports (reset)<br>`;
                    result += `PORT     STATE SERVICE<br>`;
                    
                    if (flags.includes('-sV')) {
                        result += `22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu<br>`;
                        result += `80/tcp   open  http     Apache httpd 2.4.41<br>`;
                    } else {
                        result += `22/tcp   open  ssh<br>`;
                        result += `80/tcp   open  http<br>`;
                    }
                    
                    result += `<br>Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds`;
                    consoleDiv.innerHTML = `<div class="opacity-50 select-none mb-2">$ nmap ${flags} ${target}</div>` + result;
                    nmapBtn.disabled = false;
                    nmapBtn.innerText = 'Run Scan';
                }, 1500);
            });
        }

        // DORK SIMULATOR
        const dorkContainer = document.getElementById('dork-buttons');
        if (dorkContainer) {
            const dorkInput = document.getElementById('dork-input');
            dorkContainer.querySelectorAll('button').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    dorkInput.value = e.target.getAttribute('data-val');
                });
            });
        }

        // PASSWORD SIMULATOR
        const passInput = document.getElementById('pass-input');
        if(passInput) {
            passInput.addEventListener('keyup', (e) => {
                const p = e.target.value;
                let score = 0;
                if (p.length > 8) score++;
                if (p.length > 12) score++;
                if (/[A-Z]/.test(p)) score++;
                if (/[0-9]/.test(p)) score++;
                if (/[^A-Za-z0-9]/.test(p)) score++;

                const colors = ['bg-red-500', 'bg-red-400', 'bg-yellow-500', 'bg-blue-400', 'bg-green-500', 'bg-green-400'];
                const labels = ['Very Weak', 'Weak', 'Moderate', 'Good', 'Strong', 'Uncrackable'];
                const times = ["Instantly", "Seconds", "Minutes", "Hours/Days", "Years", "Centuries"];

                document.getElementById('pass-bar').className = `h-full transition-all duration-500 ${colors[score]}`;
                document.getElementById('pass-bar').style.width = `${(score / 5) * 100}%`;
                document.getElementById('pass-strength-text').innerText = `Strength: ${labels[score]}`;
                document.getElementById('pass-time-text').innerText = `Time to Crack: ${times[score]}`;
            });
        }
    </script>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/')
def home():
    # Default route redirects to intro
    return redirect(url_for('module_view', module_id='intro'))

@app.route('/module/<module_id>')
def module_view(module_id):
    # Find the requested module
    active_module = next((item for item in CURRICULUM if item['id'] == module_id), None)
    
    # Error handling for invalid IDs
    if not active_module:
        return "Module not found", 404
    
    # Render the template with the data
    return render_template_string(
        HTML_TEMPLATE, 
        curriculum=CURRICULUM, 
        active_module=active_module
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)