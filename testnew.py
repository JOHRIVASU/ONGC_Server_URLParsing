import streamlit as st
import re
import networkx as nx
import matplotlib.pyplot as plt
import paramiko
import time
from io import StringIO
import os
import requests
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from textwrap import wrap

if 'ospf_data' not in st.session_state:
    st.session_state.ospf_data = {
        'Full': [],
        '2Way': [],
        'Exchange': [],
        'Other': []
    }
if 'domain_reports' not in st.session_state:
    st.session_state.domain_reports = []


def sanitize_text(text):
    """Sanitize and clean up non-ASCII or problematic characters."""
    replacements = {
        '\xa0': ' ', '\u2019': "'", '\u2018': "'", '\u201c': '"',
        '\u201d': '"', '\u2014': '-', '\u00a0': ' ', '\u2026': '...'
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return re.sub(r'[^\x00-\x7F]+', '', text).strip()


def fetch_reputation_data(domain):
    """Domain reputation analysis."""
    api_key = os.getenv("INSIGHT_API_KEY")
    if not api_key:
        return "🚫 Error: API key not found in environment variables."

    query_payload = {
        "query": f"Give a reputation and threat analysis of the domain {domain}.",
        "search_depth": "advanced",
        "include_answer": True,
        "include_raw_content": False
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post("https://api.tavily.com/search", headers=headers, json=query_payload)
        response.raise_for_status()
        data = response.json()
        formatted = create_detailed_report(domain, data)
        st.session_state.domain_reports.append((domain, formatted))
        return formatted

    except requests.exceptions.HTTPError as e:
        return f"❌ HTTP Error: {e.response.status_code} - {e.response.reason}"
    except Exception as e:
        return f"❌ Request Failed: {str(e)}"
    
def create_detailed_report(domain, data):
    """Format the report content for the given domain."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = sanitize_text(data.get("answer", "No summary available."))

    lines = [
        "=" * 100,
        "🛡️DOMAIN INTELLIGENCE REPORT",
        f"📅 Timestamp         : {timestamp}",
        f"🌐 Analyzed Domain   : {domain}",
        f"🗣️ Languages         : English | हिंदी",
        "=" * 100,
        "\n🔍 Summary Insight",
        "-" * 100,
        summary,
        ""
    ]

    sources = data.get("results", [])
    if sources:
        lines.append("📚 Reviewed Intelligence Sources")
        lines.append("-" * 100)
        for i, source in enumerate(sources[:5], 1):
            url = source.get("url", "Unknown URL")
            content = sanitize_text(source.get("content", "No description."))
            lines.append(f"{i}. 🔗 {url}")
            for wrapped in wrap(content, 90):
                lines.append(f"    {wrapped}")
            lines.append("")
    else:
        lines.append("⚠️ No supporting sources provided.")

    if data.get("related_searches"):
        lines.append("🔎 Related Search Queries")
        lines.append("-" * 100)
        for search in data["related_searches"]:
            lines.append(f"• {search}")
        lines.append("")

    lines.append("✅ End of Domain Report")
    lines.append("=" * 100 + "\n")
    return "\n".join(lines)

def export_reports_to_pdf(filename=None):
    """Generate a printable PDF report from stored domain checks."""
    if not st.session_state.domain_reports:
        st.warning("📭 No reports to export.")
        return

    if not filename:
        filename = f"InsightShield_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    margin = 50
    y = height - margin
    font_size = 10
    line_height = 14
    footer = "© ONGC Intelligence Report"
    wrap_limit = 100

    c.setFont("Helvetica", font_size)

    for domain, report in st.session_state.domain_reports:
        lines = sanitize_text(report).split("\n")

        c.setFont("Helvetica-Bold", font_size)
        c.drawString(margin, y, f"📘 Reputation Check: {domain}")
        y -= line_height * 2
        c.setFont("Helvetica", font_size)

        for line in lines:
            if not line.strip():
                y -= line_height
                continue
            for segment in wrap(line, wrap_limit):
                if y <= 40:
                    c.setFont("Helvetica-Oblique", 8)
                    c.drawCentredString(width / 2, 25, footer)
                    c.showPage()
                    c.setFont("Helvetica", font_size)
                    y = height - margin
                c.drawString(margin, y, segment)
                y -= line_height
        y -= line_height * 2

    c.setFont("Helvetica-Oblique", 8)
    c.drawCentredString(width / 2, 25, footer)
    c.save()
    st.success(f"📄 Report successfully exported as: {filename}")
    return filename

st.set_page_config(layout="wide", page_title="Network Tools Dashboard")

os.environ["INSIGHT_API_KEY"] = "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"

tab1, tab2, tab3 = st.tabs(["Juniper OSPF Visualizer", "Domain Reputation Check", "About"])

with tab1:
    st.title("Network diagram visualisation")

    subtab1, subtab2 = st.tabs(["SSH Auto Login", "Upload Log File"])

    with subtab1:
        st.header("SSH Auto Login to Juniper Device")
        
        with st.form("ssh_form"):
            ip_address = st.text_input("IP Address")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            submitted = st.form_submit_button("Connect and Run Commands")
            
            if submitted:
                if not all([ip_address, username, password]):
                    st.error("Please fill all required fields")
                else:
                    try:
                        with st.spinner(f"Connecting to Juniper device at {ip_address}..."):
                            commands = [
                                "cli",
                                "set cli screen-length 0",
                                "show ospf neighbor | no-more",
                                "show interfaces descriptions | no-more",
                                "exit"
                            ]

                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            client.connect(ip_address, username=username, password=password,
                                        allow_agent=False, look_for_keys=False)

                            remote = client.invoke_shell()
                            time.sleep(1)

                            output = ""
                            for cmd in commands:
                                remote.send(cmd + "\n")
                                time.sleep(2)
                                while remote.recv_ready():
                                    output += remote.recv(65535).decode("utf-8", errors='ignore')

                            client.close()
                            st.session_state.log_content = output
                            st.success("✅ OSPF neighbor data collected successfully!")
                            
                    except Exception as e:
                        st.error(f"SSH connection failed: {str(e)}")
                    
        if st.session_state.get('log_content'):
            st.subheader("OSPF Neighbor Output")
            st.text_area("Raw Output", value=st.session_state.log_content, height=300)

    with subtab2:
        st.header("Upload OSPF Neighbor Log File")
        
        uploaded_file = st.file_uploader("Upload your OSPF neighbor log", type=["log", "txt"])
        
        if uploaded_file is not None:
            st.session_state.log_content = uploaded_file.read().decode('utf-8', errors='ignore')
            st.success("File uploaded successfully!")
        
        if st.session_state.get('log_content'):
            st.subheader("Log File Content")
            st.text_area("Content", value=st.session_state.log_content[:10000] + ("..." if len(st.session_state.log_content) > 10000 else ""), 
                        height=300)

    if st.session_state.get('log_content'):
        st.header("OSPF Neighbor State Analysis")
        
        if st.button("Parse OSPF Neighbor States"):
            content = st.session_state.log_content
        
            st.session_state.ospf_data = {
                'Full': [],
                '2Way': [],
                'Exchange': [],
                'Other': []
            }
            
            interface_descriptions = {}
            desc_pattern = r'(\S+)\s+(\S+)\s+(.*)'
            desc_matches = re.finditer(desc_pattern, content)
            
            for match in desc_matches:
                interface = match.group(1)
                admin_status = match.group(2)
                description = match.group(3).strip()
                if description:  # Only store interfaces with descriptions
                    interface_descriptions[interface] = description

            ospf_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(Full|2Way|Exchange|\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+'
            matches = re.finditer(ospf_pattern, content)
            
            for match in matches:
                ip = match.group(1)
                interface = match.group(2)
                state = match.group(3)
                router_id = match.group(4)
                description = interface_descriptions.get(interface, "No description")
                
                neighbor_info = {
                    "interface": interface,
                    "ip": ip,
                    "router_id": router_id,
                    "state": state,
                    "description": description  
                }
                
                if state == "Full":
                    st.session_state.ospf_data['Full'].append(neighbor_info)
                elif state == "2Way":
                    st.session_state.ospf_data['2Way'].append(neighbor_info)
                elif state == "Exchange":
                    st.session_state.ospf_data['Exchange'].append(neighbor_info)
                else:
                    st.session_state.ospf_data['Other'].append(neighbor_info)
            
            st.success("OSPF neighbor states parsed successfully!")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Full State", len(st.session_state.ospf_data['Full']))
            col2.metric("2Way State", len(st.session_state.ospf_data['2Way']))
            col3.metric("Exchange State", len(st.session_state.ospf_data['Exchange']))
            col4.metric("Other States", len(st.session_state.ospf_data['Other']))

    if st.session_state.ospf_data['Full'] or st.session_state.ospf_data['2Way'] or st.session_state.ospf_data['Exchange']:
        st.header("OSPF Neighbor Details by State")
        
        tab_full, tab_2way, tab_exchange, tab_other = st.tabs(["Full State", "2Way State", "Exchange State", "Other States"])
        
        with tab_full:
            if st.session_state.ospf_data['Full']:
                st.write("Full State Neighbors (Fully Adjacent):")
                st.dataframe(st.session_state.ospf_data['Full'])
            else:
                st.warning("No neighbors in Full state")
        
        with tab_2way:
            if st.session_state.ospf_data['2Way']:
                st.write("2Way State Neighbors (Multi-access networks only):")
                st.dataframe(st.session_state.ospf_data['2Way'])
            else:
                st.warning("No neighbors in 2Way state")
        
        with tab_exchange:
            if st.session_state.ospf_data['Exchange']:
                st.write("Exchange State Neighbors (Exchanging Database Descriptors):")
                st.dataframe(st.session_state.ospf_data['Exchange'])
            else:
                st.warning("No neighbors in Exchange state")
        
        with tab_other:
            if st.session_state.ospf_data['Other']:
                st.write("Other State Neighbors:")
                st.dataframe(st.session_state.ospf_data['Other'])
            else:
                st.warning("No neighbors in other states")

    if st.session_state.ospf_data['Full'] or st.session_state.ospf_data['2Way'] or st.session_state.ospf_data['Exchange']:
        st.header("Network Diagram Configuration")
        states_to_include = st.multiselect(
            "Select OSPF states to visualize:",
            options=['Full', '2Way', 'Exchange', 'Other'],
            default=['Full']
        )
        options = []
        full_links = []
        
        for state in states_to_include:
            for neighbor in st.session_state.ospf_data[state]:
                label = f"[{state}] {neighbor['interface']} → {neighbor['router_id']}"
                options.append(label)
                full_links.append({
                    "state": state,
                    "interface": neighbor['interface'],
                    "ip": neighbor['ip'],
                    "router_id": neighbor['router_id'],
                    "description": neighbor['description']
                })
        
        if not options:
            st.warning("No neighbors selected for visualization.")
        else:
            selected_labels = st.multiselect("Select neighbors to include:", options)
            col1, col2 = st.columns(2)
            with col1:
                central_node = st.text_input("Central node name", value="DLI-SM3")
                node_size = st.slider("Node size", 500, 5000, 2000)
                show_descriptions = st.checkbox("Show interface descriptions", value=True)
                show_ip_addresses = st.checkbox("Show IP addresses", value=True)
            with col2:
                layout = st.selectbox("Layout algorithm", ["spring", "circular", "kamada_kawai"])
                color_by_state = st.checkbox("Color nodes by OSPF state", value=True)
                show_legend = st.checkbox("Show legend", value=True)
            
            if st.button("Generate OSPF State Diagram"):
                if not selected_labels:
                    st.warning("Please select at least one neighbor to visualize.")
                else:
                    G = nx.Graph()
                    G.add_node(central_node)
                    state_colors = {
                        'Full': 'lightgreen',
                        '2Way': 'lightyellow',
                        'Exchange': 'lightcoral',
                        'Other': 'lightgray'
                    }

                    node_colors = ['lightblue']  
                    for label in selected_labels:
                        idx = options.index(label)
                        link_data = full_links[idx]
                        edge_label_parts = []
                        if show_ip_addresses:
                            edge_label_parts.append(link_data['ip'])
                        edge_label_parts.append(link_data['interface'])
                        if show_descriptions and link_data['description'] != "No description":
                            edge_label_parts.append(link_data['description'])
                        
                        edge_label = "\n".join(edge_label_parts)
                        
                        G.add_edge(central_node, link_data['router_id'], 
                                  label=edge_label)
                        
                        if color_by_state:
                            node_colors.append(state_colors.get(link_data['state'], 'lightgray'))
                        else:
                            node_colors.append('lightblue')
                    
                    if layout == "spring":
                        pos = nx.spring_layout(G, seed=42)
                    elif layout == "circular":
                        pos = nx.circular_layout(G)
                    else:
                        pos = nx.kamada_kawai_layout(G)
                
                    plt.figure(figsize=(16, 12))
                    nx.draw(G, pos, with_labels=True,
                            node_color=node_colors,
                            node_size=node_size,
                            font_size=10,
                            font_weight='bold')
                    
                    edge_labels = nx.get_edge_attributes(G, 'label')
                    nx.draw_networkx_edge_labels(G, pos,
                                               edge_labels=edge_labels,
                                               font_color='darkgreen',
                                               font_size=8)
                    
                    plt.title("OSPF Neighbor States", fontsize=16)
                    

                    if color_by_state and show_legend:
                        handles = []
                        for state, color in state_colors.items():
                            if state in states_to_include:
                                handles.append(plt.Line2D([0], [0], marker='o', color='w', 
                                                      label=state, markerfacecolor=color, markersize=10))
                        plt.legend(handles=handles, title="OSPF States", loc='upper right')
                    
                    plt.axis('off')
                    
                    st.pyplot(plt)
                    
                    plt.savefig("ospf_states.png", bbox_inches='tight')
                    with open("ospf_states.png", "rb") as f:
                        st.download_button("Download Diagram", f, file_name="ospf_states.png")

with tab2:
    st.title("Domain Reputation Analysis")
    
    with st.expander("About Domain Reputation Check"):
        st.write("""
        This tool checks the reputation of the worldwide domains. 
        It provides threat intelligence, security analysis, and historical reputation data.
        """)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        domain = st.text_input("Enter domain to analyze (e.g., example.com)", "")
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("Analyze Domain")
    
    if analyze_btn and domain:
        with st.spinner(f"Analyzing domain {domain}..."):
            report_output = fetch_reputation_data(domain)
            st.markdown(report_output.replace("\n", "  \n"))
    
    if st.session_state.domain_reports:
        st.subheader("Previous Reports")
        for i, (domain, report) in enumerate(st.session_state.domain_reports):
            with st.expander(f"Report {i+1}: {domain}"):
                st.markdown(report.replace("\n", "  \n"))
        
        if st.button("Export All Reports to PDF"):
            pdf_file = export_reports_to_pdf()
            with open(pdf_file, "rb") as f:
                st.download_button(
                    "Download PDF Report",
                    f,
                    file_name=pdf_file,
                    mime="application/pdf"
                )

with tab3:
    st.title("About This Application")
    st.write("""
    ### Network Tools Dashboard
    
    This application combines two powerful network analysis tools:
    
    1. **Juniper OSPF Neighbor State Visualizer** - Helps network engineers visualize OSPF neighbor relationships
    2. **Domain Reputation Check** - Provides security analysis of domains using threat intelligence
    
    ### Features
    
    - SSH auto-login to Juniper devices
    - OSPF neighbor state analysis
    - Interactive network diagrams
    - Domain threat intelligence reports
    - PDF report generation
    """)