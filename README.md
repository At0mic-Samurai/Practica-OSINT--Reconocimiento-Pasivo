# Practica-OSINT--Reconocimiento-Pasivo
El objetivo del reconocimiento pasivo es buscar y recopilar información pública expuesta en internet sin interactuar directamente con el sistema, esto mediante distintas herramientas OSINT para facilitar fases posteriores del pentesting.

## Resumen Ejecutivo
El presente análisis OSINT tiene como objetivo evaluar la exposición de la infraestructura y credenciales de la organización. Se identificó que la red expone servicios críticos como servidores VPN y fuga de información de arquitectura interna, además de depender de un proveedor externo para el filtrado de correo corporativo. El hallazgo de mayor impacto es la presencia de credenciales de administradores en bases de datos de filtraciones públicas, lo que facilita ataques de intrusión. Como medida prioritaria, se recomienda implementar de forma obligatoria la autenticación multifactor (MFA) en todos los accesos corporativos, purgar los registros DNS que exponen la red interna y forzar la rotación inmediata de contraseñas comprometidas.

## Objetivo General
El objetivo del reconocimiento pasivo es buscar y recopilar información pública expuesta en internet sin interactuar directamente con el sistema, esto mediante distintas herramientas OSINT para facilitar fases posteriores del hacking ético.
 
1. **¿Cuál es el punto del reto?**
El punto es entender cómo trabajan los atacantes en la vida real cuando quieren vulnerar una empresa. Los humanos somos predecibles y reutilizamos contraseñas. En el pasado, ha habido enormes filtraciones de datos (hacks a Yahoo, LinkedIn, MySpace, foros de internet, etc.). Los atacantes recopilaron todas esas contraseñas filtradas en un solo lugar.

2. **¿Qué es BreachParse?**
BreachParse es un buscador de texto ultra rápido. Es como un archivo de texto gigante de decenas de GB, donde cada línea dice el correo y la contraseña filtrada. BreachParse usa herramientas de Linux eficientes (como grep y ripgrep) para escanear ese archivo gigante en segundos y sacar solo las líneas que coincidan con lo que se buscas (por ejemplo, todo lo que termine en @dominio.com)

3. **¿Qué es BreachCompilation?**
Es una compilación de brechas de seguridad, es decir, un volcado masivo con más de 1,400 millones de credenciales (correos y contraseñas) que se han filtrado a lo largo de los años. Es un recurso público que usan los pentesters (hackers éticos) para probar la seguridad de las empresas.

4. **¿Qué es un enlace magnet?**
Un enlace magnet es una forma de compartir archivos sin necesidad de un servidor central. En lugar de descargar el archivo de una sola página web (que colapsaría por el peso de 41 GB), el enlace magnet le dice a tu computadora: "Conéctate a esta red de personas que ya tienen el archivo y descárgalo por pedacitos de todos ellos a la vez".

5. **¿Qué es BitTorrent?**
Son los clientes (los programas) que entienden esos enlaces magnet. BitTorrent es el protocolo (la tecnología) de intercambio de archivos peer-to-peer (P2P). uTorrent (o qBittorrent, Transmission, etc.) es el programa que se instala para abrir el enlace magnet. Cuando se abre el magnet, el programa se conecta a la red, encuentra a otras personas que tienen el archivo y empieza a descargar los pedazos, al mismo tiempo que uno comparte los pedazos que ya.

>[!Note]
>En Kali Linux, el cliente que suele venir o se instala más fácil es transmission o qbittorrent. No se recomienda usar uTorrent, ya que es de Windows y trae publicidad.

## Caso 1 - Tesla 

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

### Hallazgo 2 - Proveedor de correo de Tesla

**La gerencia desea determinar si el servicio de correo electrónico de Tesla depende de un proveedor externo.**

**Objetivo**: Identificar la empresa que presta el servicio y el registro DNS que se usó como evidencia.

**Pregunta clave**: ¿Qué es un registro de tipo MX?

2. En el mismo listado de registros de tesla.com en DNSDumpster, scrollear hasta la sección de MX Records para identificar los registros públicos de intercambio de correo

Se identifica un único registro MX para Tesla:

<img width="950" height="123" alt="imagen" src="https://github.com/user-attachments/assets/51205848-c8a4-429f-8b61-dccc320192a7" />

- **Nombre del registro**: `10 tesla-com.mail.protection.outlook.com`
- **Proveedor indentificado**: `Microsoft Corp`
- **Tipo de registro DNS**: `MX (Mail Exchange) Record`
- **Dirección IP**: `52.101.8.71`
- **ASN**: `8075`
- **Nombre de ASN**: `MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation`
- **Geolocalización**: `United States`
- **Conclusión**: Se observa que Tesla usa Microsoft 365 para recibir y posiblemente filtrar su correo, ya que su registro MX apunta al servidor de protección de Outlook tesla-com.mail.protection.outlook.com, por lo tanto Tesla depende de Microsoft para el correo entrante (inbound)

<img width="740" height="325" alt="imagen" src="https://github.com/user-attachments/assets/ae3c0a69-6dc2-4411-a664-c62c1a7ea6fb" />

## Caso 2 - Anthropic

### Hallazgo 1 - Direcciones privadas en registros DNS de Anthropic

Algunos registros DNS públicos de Anthropic (anthropic.com) revelan direcciones IP asociadas con su infraestructura interna.

**Objetivo**s: Identificar los nombres de servidor y sus IP. Explicar qué tienen en común las direcciones y por qué su publicación puede ser una mala práctica.

1. Usando [DNSDumpster](https://dnsdumpster.com/) nuevamente para realizar la investigación entre los diversos registros DNS públicos se identifican un total de cuatro direcciones IP asociadas a infraestructura interna. 

| **Nombre del Servidor**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | **Registro**        | **Dirección IP** | **Fecha de consulta** |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ---------------- | --------------------- |
| `sandbox.api.anthropic.com`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Registro DNS tipo A | `10.104.0.8`     | 05/11/2026            |
| `sandbox.staging.api.anthropic.com`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Registro DNS tipo A | `10.104.0.117`   | 05/11/2026            |
| `stt.titanium-staging.api.anthropic.com`<br><br>`stt-flux.titanium staging.api.anthropic.com`<br><br>`stt-flux-a100.titanium-staging.api.anthropic.com`<br><br>`stt-flux-multi.titanium-staging.api.anthropic.com`<br><br>`stt-flux-multi-a100.titanium-staging.api.anthropic.com`<br><br>`stt-nova3.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s0.titanium-staging.api.anthropic.com`<br>  <br>`stt-nova3-s1.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s2.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s3.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s4.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s5.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s6.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s7.titanium-staging.api.anthropic.com`<br><br>`stt-nova3-s8.titanium-staging.api.anthropic.com` | Registro DNS tipo A | `10.104.0.5`     | 05/11/2026            |
| `stt.titanium.api.anthropic.com`<br><br>`stt-flux.titanium.api.anthropic.com`<br><br>`stt-flux-a100.titanium.api.anthropic.com`<br><br>`stt-flux-multi.titanium.api.anthropic.com`<br><br>`stt-flux-multi-a100.titanium.api.anthropic.com`<br><br>`stt-nova3.titanium.api.anthropic.com`<br><br>`stt-nova3-s0.titanium.api.anthropic.com`<br><br>`stt-nova3-s1.titanium.api.anthropic.com`<br><br>`stt-nova3-s2.titanium.api.anthropic.com`<br><br>`stt-nova3-s3.titanium.api.anthropic.com`<br><br>`stt-nova3-s4.titanium.api.anthropic.com`<br><br>`stt-nova3-s5.titanium.api.anthropic.com`<br><br>`stt-nova3-s6.titanium.api.anthropic.com`<br><br>`stt-nova3-s7.titanium.api.anthropic.com`<br><br>`stt-nova3-s8.titanium.api.anthropic.com`                                                                                                                           | Registro DNS tipo A | `10.104.0.6`     | 05/11/2026            |

>[!Note]
>La infraestructura analizada es dinámica y los registros DNS pueden variar con el tiempo.

2. ¿Qué tienen en común las direcciones IP?

Lo que tienen en común las direcciones IP es que pertenecen al rango privado de la clase A, es decir no son enrutables en internet como tal y son usadas en redes LAN (infraestructura interna). Según RFC 1918 el rango privado de la clase A, va de 10.0.0.0/8 a 10.255.255.255/8 por lo que las direcciones IP pertenecen a este rango.
Además las IPs 10.104.0.5 y 10.104.0.6 se repiten en múltiples nombres de host distintos, lo que podría indicar por ejemplo, dos servicios o alias que corren en la misma máquina.

3. Riesgo y recomendación

- Pilar afectado: Confidencialidad
- Riesgo: El principal riesgo derivado de este hallazgo es la fuga de información de arquitectura interna. Aunque las direcciones IP son privadas y no se pueden atacar directamente desde la WAN, el hecho de que estén expuestas públicamente junto con el nombre de host, revela información que debería ser confidencial como la topología interna, los nombres de posibles proyectos o servicios internos, entornos de prueba y el segmento de red que podría estar en uso (10.104.0.0/24). Esto facilita a un atacante las fases de reconocimiento y escaneo en caso que logre acceder a la red mediante técnicas como phishing o VPN comprometida, permitiéndole escanear directamente esos rangos para buscar vulnerabilidades, realizar movimientos laterales y comprometer servicios críticos.
- Recomendación: Eliminar estos registros de la zona DNS pública. Las direcciones IP de infraestructura interna deben resolverse exclusivamente a través de un servidor DNS interno de modo que solo sean visibles para dispositivos que ya estén dentro de la red corporativa o conectados a una VPN segura. Del mismo modo se recomienda implementar autenticación multifactor obligatoria para todos los accesos a la VPN corporativa. Esto mitiga el riesgo de que un atacante entre a la red interna usando credenciales robadas. Finalmente se recomienda implementación de políticas de DLP (Data Loss Prevention) para monitorear y bloquear la salida de información sensible o código fuente hacia el exterior, mitigando el riesgo de divulgación (Dissclosure) de información.
