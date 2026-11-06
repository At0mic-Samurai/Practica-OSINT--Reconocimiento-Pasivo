# Practica-OSINT--Reconocimiento-Pasivo
El objetivo del reconocimiento pasivo es buscar y recopilar información pública expuesta en internet sin interactuar directamente con el sistema, esto mediante distintas herramientas OSINT para facilitar fases posteriores del pentesting.

## Resumen Ejecutivo
El presente análisis OSINT tiene como objetivo evaluar la exposición de la infraestructura y credenciales de la organización. Se identificó que la red expone servicios críticos como servidores VPN y fuga de información de arquitectura interna, además de depender de un proveedor externo para el filtrado de correo corporativo. El hallazgo de mayor impacto es la presencia de credenciales de administradores en bases de datos de filtraciones públicas, lo que facilita ataques de intrusión. Como medida prioritaria, se recomienda implementar de forma obligatoria la autenticación multifactor (MFA) en todos los accesos corporativos, purgar los registros DNS que exponen la red interna y forzar la rotación inmediata de contraseñas comprometidas.

## Objetivo General
El objetivo del reconocimiento pasivo es buscar y recopilar información pública expuesta en internet sin interactuar directamente con el sistema, esto mediante distintas herramientas OSINT para facilitar fases posteriores del hacking ético.
 
1. **¿Cuál es el punto del reto?**
El punto es entender cómo trabajan los atacantes en la vida real cuando quieren vulnerar una empresa (en este caso, Toyota). Los humanos somos predecibles y reutilizamos contraseñas. En el pasado, ha habido enormes filtraciones de datos (hacks a Yahoo, LinkedIn, MySpace, foros de internet, etc.). Los atacantes recopilaron todas esas contraseñas filtradas en un solo lugar.
El objetivo del reto es que tú, como analista, aprendas a buscar en esa "base de datos de contraseñas robadas" si el usuario administrador del dominio toyota.de apareció en alguna filtración. Si aparece, significa que un atacante podría usar esa misma contraseña para intentar entrar a la VPN de Toyota.

2. **¿Qué es BreachParse?**
BreachParse es solo un buscador de texto súper rápido
Imagina que tienes un archivo de texto gigante, como una guía telefónica de 41 GB, donde cada línea dice el correo y la contraseña filtrada. Si usaras el buscador de Windows o abrieras el archivo con un editor de texto normal, tu computadora explotaría por falta de memoria. BreachParse usa herramientas de Linux súper eficientes (como grep y ripgrep) para escanear ese archivo gigante en segundos y sacar solo las líneas que coincidan con lo que buscas (por ejemplo, todo lo que termine en @toyota.de).

3. **¿Qué es BreachCompilation?**
Es exactamente lo que su nombre en inglés dice: una compilación de brechas de seguridad. Es un volcado masivo (unos 41 GB comprimidos) con más de 1,400 millones de credenciales (correos y contraseñas) que se han filtrado a lo largo de los años. Es un recurso público que usan los pentesters (hackers éticos) para probar la seguridad de las empresas.

4. **¿Qué es un enlace magnet?**
El archivo del README dice magnet:?xt=.... Un enlace magnet es una forma de compartir archivos sin necesidad de un servidor central. En lugar de descargar el archivo de una sola página web (que colapsaría por el peso de 41 GB), el enlace magnet le dice a tu computadora: "Conéctate a esta red de personas que ya tienen el archivo y descárgalo por pedacitos de todos ellos a la vez".

5. **¿Qué son uTorrent y BitTorrent?**
Son los clientes (los programas) que entienden esos enlaces magnet. BitTorrent es el protocolo (la tecnología) de intercambio de archivos peer-to-peer (P2P). uTorrent (o qBittorrent, Transmission, etc.) es el programa que instalas en tu compu para abrir el enlace magnet. Cuando abres el magnet, el programa se conecta a la red, encuentra a otras personas que tienen el archivo y empieza a descargar los pedazos, al mismo tiempo que tú compartes los pedazos que ya descargaste.

>[!Note]
>En Kali Linux, el cliente que suele venir o se instala más fácil es transmission o qbittorrent. No se recomienda usar uTorrent, ya que es de Windows y trae publicidad.

---
### Hallazgo 1 - Servidor VPN de Tesla en Países Bajos

**Tras los cambios en sus políticas de trabajo remoto, Tesla (tesla.com) desplegó servidores VPN para sus sucursales en Europa y Estados Unidos, siguiendo una convención común de nombres.**

**Objetivo:** Identificar el nombre de host y la dirección IP del servidor VPN correspondiente a la sucursal de los Países Bajos.

**Pregunta clave:** ¿Cuál es el nombre del servidor y su dirección IP? *La pista indica que el prefijo del nombre corresponde a un código de aeropuerto.*

1. Se usará la herramienta [DNSDumpster](https://dnsdumpster.com/) para realizar la investigación de subdominios de la empresa y buscar el correspondiente al servidor VPN de Países Bajos entre los diversos registros DNS públicos.

	Query dominio principal:
	`tesla.com` 

  <img width="1322" height="597" alt="imagen" src="https://github.com/user-attachments/assets/37d77c19-7e33-4e65-88c3-1d9e857ad9c5" />

La bandera señalada pertenece a Netherlands (Países Bajos), un país ubicado en Europa cuya capital es la ciudad de Amsterdam, en la provincia Holanda Septentrional. Esto sugiere que, junto con Estados Unidos e Irlanda, Países Bajos es una de las distribuciones geográficas de hosting.

La herramienta nos muestra 50 registros de un total de 220, sin embargo es posible que el registro objetivo se encuentre entre estos. Para ello se aplica una búsqueda rápida de palabras clave en la página con **Ctrl + F** 

Palabras clave referentes a un servidor VPN:
- gateway: 8 coincidencias
- vpn: sin coincidencias 
- portal: sin coincidencias
- tunel: sin coincidencias
	 
Dado que se nos proporciona una referencia sobre el prefijo del nombre y su relación con un código de areopuerto, y estamos buscando el servidor ubicado en Países Bajos, se ha buscado en [IATA Codes](https://iata-codes.com/es/) los códigos de las principales ciudades de los Países Bajos (Ámsterdam, que es la capital y la ciudad más poblada, seguida de Róterdam, La Haya, Utrecht y Eindhoven. Estas ciudades son importantes tanto cultural como económicamente en el país)

<img width="731" height="182" alt="imagen" src="https://github.com/user-attachments/assets/85b54f07-b072-472d-a4e6-d36f8d4ee248" />

- **ams: 1 coincidencia**

<img width="1320" height="843" alt="imagen" src="https://github.com/user-attachments/assets/7341f048-2c31-4211-a943-137292779dc3" />

Este registro representa un posible candidato de servidor de VPN. Para acotar un poco más la búsqueda, se procede a analizar la IP, el nombre completo del host, y validar la ubicación del ASN.
- **ams** = código IATA del aeropuerto de Amsterdam-Schiphol
- **gpgw** = probable acrónimo de GlobalProtect Gateway (solución VPN de Palo Alto Networks para usuarios remotos)
- **Ubicación** del ASN: The Netherlands (Países Bajos)
- **Validación de geolocalización:**

<img width="755" height="352" alt="imagen" src="https://github.com/user-attachments/assets/48c700ed-fe80-4edf-904d-aff8d964d6b2" />

Con estas validaciones adicionales se descartan las demás coincidencias y se concluye que el registro DNS pertenece al servidor VPN de Tesla ubicado en Países Bajos. 
- **Dominio principal**: `telsa.com`
- **Hostname**: `ams13-gpgw1.tesla.com`
- **Dirección IPv4**: `199.120.50.30`
- **ASN**: `394161`
- **Nombre del ASN**: `TESLA - Tesla Motors, Inc.`
- **Geolocalización**: `The Netherlands` 
- **Conclusión**: Es muy probable que se trate de una interfaz de un firewall Palo Alto que gestiona el portal VPN o la interfaz de un balanceador de carga que está antes de varios firewalls para repartir las solicitudes de múltiples accesos simultáneos.

---
### Hallazgo 2 - Proveedor de correo de Tesla
	
