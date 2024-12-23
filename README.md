# Segundo Laboratorio de Redes de Computadoras

## Descripción General

Este laboratorio consiste en la creación y configuración de una red simulada en un entorno virtual utilizando Mininet. Se trabajó con dos topologías distintas y se implementaron diversas funcionalidades relacionadas con el manejo de paquetes IP y protocolos de enrutamiento.

## Objetivo del Laboratorio

El objetivo principal fue profundizar en el conocimiento de redes mediante la implementación de mecanismos de encaminamiento, manejo de paquetes y protocolos de enrutamiento. Esto incluyó:

### Manejo de paquetes IP:
- Implementación del algoritmo Longest Prefix Match (LPM) para la selección de rutas.
- Procesamiento y manejo de paquetes ICMP.

### Protocolos de enrutamiento:
- Implementación del protocolo OSPF (Open Shortest Path First) para generar y actualizar las tablas de forwarding.
- Uso del algoritmo Dijkstra para calcular el camino más corto entre nodos de la red.

## Topologías

Se trabajó con dos topologías diferentes para la simulación:

### Topología 1:
- 1 cliente
- 3 routers
- 2 servidores

### Topología 2:
- Similar a la Topología 1, pero extendida con 5 routers en lugar de 3

Estas topologías permitieron evaluar el rendimiento y la complejidad de las implementaciones bajo diferentes condiciones de red.

## Implementaciones Realizadas

### 1. Manejo de Paquetes IP

#### Longest Prefix Match (LPM):
- Implementación para la selección óptima de rutas basándose en el prefijo más largo que coincide con la dirección IP de destino.

#### Manejo de paquetes ICMP:
- Procesamiento de mensajes ICMP como "Echo Request" y "Echo Reply".
- Respuesta a paquetes ICMP de error (por ejemplo, "Destination Unreachable").

### 2. Protocolo de Enrutamiento - OSPF
- Implementación del protocolo OSPF para la generación y sincronización de las tablas de forwarding.
- Uso del algoritmo Dijkstra para calcular el camino más corto entre nodos, optimizando el enrutamiento en la red.
- Sincronización de las tablas de enrutamiento en toda la topología para garantizar una red consistente.

## Herramientas Utilizadas

- **Mininet**: Para la simulación de las topologías de red.
- **Python**: Implementación de las funcionalidades de manejo de paquetes y enrutamiento.
- **Wireshark**: Captura y análisis de paquetes para la validación de los resultados.
- **Disktrak**: Utilizado dentro del algoritmo Dijkstra para el cálculo de caminos más cortos.

## Instrucciones para la Ejecución

1. Instalar Mininet en el entorno de trabajo.
2. Configurar las topologías en Mininet:
   - Utilizar los archivos de configuración proporcionados para cada topología.
3. Ejecutar los scripts de Python correspondientes para:
   - Generar las tablas de forwarding.
   - Manejar los paquetes IP e ICMP.
4. Analizar el funcionamiento de la red mediante capturas de Wireshark.

## Resultados Esperados

- Validación de que el cliente puede comunicarse con los servidores mediante rutas calculadas dinámicamente.
- Confirmación de que las tablas de forwarding se sincronizan correctamente utilizando OSPF.
- Correcto manejo de paquetes ICMP, incluyendo respuestas a mensajes de error y eco.

## Conclusiones

Este laboratorio permitió comprender y aplicar conceptos avanzados de redes, como el manejo de paquetes IP, la implementación de algoritmos de selección de rutas y el uso de protocolos de enrutamiento dinámico. Asimismo, el uso de herramientas como Mininet y Wireshark facilitó la simulación y el análisis del comportamiento de la red.
