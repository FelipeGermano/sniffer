import psutil
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread

# Função para obter o nome do processo pelo PID
def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

# Função para listar os processos abertos
def get_process_list():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append((proc.info['pid'], proc.info['name']))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

# Função para processar pacotes de um PID específico
def process_packet(packet, target_pid, root):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        # Verificar se o pacote pertence ao processo alvo
        if proto == "TCP" and TCP in packet:
            port = packet[TCP].sport
        elif proto == "UDP" and UDP in packet:
            port = packet[UDP].sport
        else:
            port = None

        def msg(message):
            log_text = tk.Text(root, height=10, state=tk.DISABLED)
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, message + "\n")
            log_text.config(state=tk.DISABLED)
            log_text.see(tk.END)

        if port:
            for conn in psutil.net_connections(kind=proto.lower()):
                if conn.laddr.port == port and conn.pid == target_pid:
                    process_name = get_process_name(conn.pid)
                    msg(f"[{datetime.now()}] {proto} Packet:")
                    msg(f"  Source: {ip_src}:{port}")
                    msg(f"  Destination: {ip_dst}")
                    msg(f"  Process: {process_name}")
                    msg("-----------------------------------")
                    break

# Função para iniciar o sniffing de pacotes
def start_sniffing(pid, root):
    try:
        print(f"Iniciando interceptação para o processo PID {pid}... (Ctrl+C para parar)")
        sniff(prn=lambda pkt: process_packet(pkt, pid, root), store=False)
    except KeyboardInterrupt:
        print("\nEncerrando interceptação de pacotes.")

# Função para iniciar a captura em uma thread separada
def start_sniffing_thread(pid, root):
    sniffing_thread = Thread(target=start_sniffing, args=(pid, root,))
    sniffing_thread.daemon = True
    sniffing_thread.start()

# Interface Gráfica
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Frame para lista de processos
        self.frame_processes = ttk.Frame(root)
        self.frame_processes.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.label_processes = ttk.Label(self.frame_processes, text="Selecione um processo:")
        self.label_processes.pack(anchor=tk.W)

        self.process_listbox = tk.Listbox(self.frame_processes, height=20, width=50)
        self.process_listbox.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        self.refresh_button = ttk.Button(self.frame_processes, text="Atualizar Lista", command=self.populate_process_list)
        self.refresh_button.pack(pady=5)

        # Botão para iniciar o sniffing
        self.start_button = ttk.Button(root, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(pady=5)

        # Área de logs
        self.log_text = tk.Text(root, height=10, state=tk.DISABLED)
        self.log_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        self.populate_process_list()

    def populate_process_list(self):
        self.process_listbox.delete(0, tk.END)
        processes = get_process_list()
        for pid, name in processes:
            self.process_listbox.insert(tk.END, f"{pid} - {name}")

    def start_capture(self):
        selected = self.process_listbox.curselection()
        if not selected:
            messagebox.showwarning("Aviso", "Por favor, selecione um processo.")
            return

        selected_text = self.process_listbox.get(selected)
        pid = int(selected_text.split(" - ")[0])
        
        self.log_message(f"Iniciando captura para o processo PID {pid}...")
        start_sniffing_thread(pid, self.root)

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

# Iniciar aplicação
def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
