# Packet Sniffer com Interface Gráfica (GUI)

Este projeto Python fornece uma interface gráfica para interceptar e monitorar pacotes de rede associados a processos específicos em execução no sistema. Ele combina o poder da biblioteca `scapy` para captura de pacotes com a biblioteca `tkinter` para criar uma interface amigável ao usuário.

## Recursos

- **Listar Processos Ativos**: Exibe todos os processos atualmente em execução.
- **Selecionar um Processo**: Permite selecionar um processo pelo seu PID para monitorar a atividade de rede.
- **Captura de Pacotes em Tempo Real**: Intercepta e exibe pacotes de rede associados ao processo selecionado.
- **Interface Gráfica**: Interface amigável desenvolvida com `tkinter`.

## Requisitos

- Python 3.7+
- Bibliotecas:
  - `psutil`
  - `scapy`

Para instalar as bibliotecas necessárias, execute:
```bash
pip install psutil scapy
```

## Uso

1. **Execute o Script**:
   Execute o script com privilégios de administrador:
   ```bash
   python process_packet.py
   ```

2. **Selecione um Processo**:
   - A interface gráfica exibirá uma lista de processos ativos.
   - Selecione o processo que deseja monitorar.

3. **Inicie a Captura**:
   - Clique no botão "Iniciar Captura" para começar a interceptar pacotes associados ao processo selecionado.

4. **Visualize os Logs**:
   - Os logs em tempo real dos pacotes capturados aparecerão na área de logs da interface.

## Exemplo

![Exemplo](https://cloud.screenpresso.com/RP2FvFRBabDR/2025_01_11_18h21_57_original.png)

## Observações

- **Privilégios de Administrador**: O script requer privilégios administrativos para capturar pacotes.
- **Npcap ou WinPcap**: Certifique-se de que o `Npcap` ou `WinPcap` está instalado no seu sistema.
  - Baixe e instale o [Npcap](https://npcap.com/) se ainda não estiver instalado.
- **Conformidade Legal**: Use esta ferramenta apenas em redes e sistemas que você tem permissão para monitorar.

## Limitações Conhecidas

- A ferramenta pode não capturar todos os pacotes devido a restrições no sistema operacional ou permissões insuficientes.
- Funciona apenas em sistemas onde o `Npcap` ou `WinPcap` está corretamente instalado.

## Aviso

Esta ferramenta é destinada apenas para fins educacionais e de monitoramento de rede legítimo. O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

