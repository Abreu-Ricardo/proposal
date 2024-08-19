import matplotlib.pyplot as plt


### Img dos resultados da latencia testada por ping
num_pkts = ["100","1000","10000"]

media_rot   = [0.038, 0.042, 0.046 ]
plt.plot(num_pkts, media_rot, 'o-', label="roteamento")


media_redir = [0.051, 0.054, 0.051]
plt.plot(num_pkts, media_redir, '-xr',label="redirecionamento")


plt.xlabel('Número de pacotes enviados')
plt.ylabel('Tempo de resposta(ms)')

plt.grid(color = 'black', linestyle = '-', linewidth = 0.5)

plt.legend()
plt.show()


################################################################################


### Img da vazao encontrada pelo iperf3
#fluxos = ["1","2","3","4","5"]
#
## taxa de transferencia por roteamento
#rot_transfer  = [33.4, 35.8, 36.2, 36.5, 34.5 ]
#plt.plot(fluxos, rot_transfer, 'o-', label="roteamento")
#
## taxa de transferencia por redirecionamento
#redir_transfer  = [ 35.1, 36.5, 35.8, 36.6, 37.3]
#plt.plot(fluxos, redir_transfer, '-xr',label="redirecionamento")
#
#
#plt.xlabel('Número de fluxos')
#plt.ylabel('Taxa de transferência(GBytes)')
#
#plt.grid(color = 'black', linestyle = '-', linewidth = 0.5)
#
#plt.legend()
#plt.show()
