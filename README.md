# 🛠️ SCCM Automation & Administration Scripts

Repositório central de **scripts e ferramentas de automação** desenvolvidos para otimizar a administração, manutenção e execução de tarefas no **Microsoft Endpoint Configuration Manager (SCCM/MECM)**.

O objetivo deste projeto é reunir scripts (PowerShell, VBScript, Batch, etc.) que facilitem o dia a dia do administrador de infraestrutura, reduzindo o trabalho manual e padronizando processos.

---

## 🚀 Funcionalidades e Categorias

Os scripts estão organizados de acordo com as seguintes frentes de automação:

*   **Gerenciamento de Clientes:** Scripts para instalação, reparo, limpeza de cache e diagnóstico do agente do SCCM.
*   **Distribuição de Software:** Automação na criação de aplicações, pacotes e implantação (*deployments*).
*   **Atualizações de Software (SUP):** Scripts auxiliares para monitoramento de compliance e limpeza de atualizações.
*   **Coleta de Dados e Relatórios:** Consultas WMI/SQL e scripts para inventário personalizado de hardware e software.
*   **Infraestrutura:** Scripts para verificação de integridade dos servidores de site (*Site Servers*) e pontos de distribuição (*DPs*).

---

## 📋 Pré-requisitos

Antes de executar os scripts, certifique-se de possuir:

*   **PowerShell 5.1** ou superior.
*   Módulo do SCCM instalado (`ConfigurationManager.psd1`).
*   Permissões de **Administrador do SCCM** (as permissões específicas variam por script).
*   Diretrizes de execução do PowerShell configuradas (ex: `Set-ExecutionPolicy RemoteSigned`).

---

## 🛠️ Como Usar

1. Clone o repositório para sua máquina ou servidor de salto (*jumpbox*):
   ```bash
   git clone https://github.com
   ```
2. Navegue até a pasta do script desejado.
3. Abra o console do PowerShell como Administrador, importe o módulo do SCCM (se necessário) e execute o script seguindo as instruções documentadas no cabeçalho do próprio arquivo.

---

## 🤝 Contribuições

Contribuições são muito bem-vindas! Se você tem um script que resolve um problema comum no SCCM:

1. Faça um **Fork** do projeto.
2. Crie uma **Branch** para sua modificação (`git checkout -b feature/NovoScript`).
3. Abra um **Pull Request** detalhando a função do script.

---

## 📝 Licença

Este projeto está sob a licença [MIT](LICENSE). Sinta-se livre para usar, modificar e distribuir.
