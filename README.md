# Pop3Filter

## Estrucutra del proyecto
En el directorio principal del repositorio podemos encontrar el Makefile principal para la construcción y los codigos fuentes correspondientes al main del server y el manejo de argumentos.
Luego encontraremos subdirectorios que reparten el trabajo de la siguiente manera:
* **docs** - Contiene el informe del trabajo.
* **manager** - Contiene el codigo fuente del server que maneja el protocolo SAP, asi como funciones de utilidad para el manejo del protocolo
* **manager-client** - Contiene el codigo fuente (y su ejecutable despues de la construcción) del cliente del protocolo SAP.
* **parsers** - Contiene el codigo fuente de todos los parsers utilizados en el trabajo
* **proxy** - Contiene el codigo fuente del proxy pop 3 
* **utils** - Contiene el codigo fuente de distintas librerias de utilidad: como la del selector, buffer, etc.


## Construcción y ejecucción
Para construir el proyecto, es tan facil como hacer un make en el directorio principal
```console
foo@bar:~/Pop3Filter/$ make all
```
Luego encontraremos el ejecutable del server en el directorio principal bajo el nombre **pop3filter** y el ejecutable del cliente dentro del directorio *manager-client* bajo el nombre **client**

## Argumentos y opciones para el proxy
El proxy lleva como argumento OBLIGATORIO la dirección del servidor origen POP3. Adicionalmente, se le puden pasar las siguientes opciones:

| Opción      | Descripción |
| ----------- | ----------- |
| -e      | Archivo donde se redirecciona el stderr       |
| -h   | Imprime la ayuda y termina        |
| -l <pop3 addr>   | Dirección donde serviría el proxy POP3        |
| -p <pop3 port>   | Puerto entrante conexiones POP3        |
| -L <mang addr>   | Dirección donde serviría el servicio de management        |
| -o <mang port>   | Puerto entrante conexiones management        |
| -P <origin port>   | Puerto del servidor POP3 en el servidor origen        |
| -t <cmd>   | Comando utilizado para las transformaciones externas.  Compatible con system(3)        |
| -v <cmd>   | Imprime información sobre la versión y termina        |  
  
 ## Comandos habilitados desde el cliente de managment
  La interfaz del cliente nos permite utilizar unos cuantos comandos para alterar el estado del proxy, o bien obtener estadisticas del mismo. Todos los comandos se escriben en lowercase.
  
  | Comando      | Descripción |
| ----------- | ----------- |
| help      | Devuelve la lista de comandos disponibles |
| historic  | Devuelve la cantidad de conexiones historicas|
| current   | Devuelve la cantidad de conexiones actuales |
| bytes  | Devuelve la cantidad de bytes transferidos|
| getbuff   | Devuelve el tamaño del buffer utilizado|
| setbuff  <buffsize> | Cambia el tamaño del buffer utilizado|
| gettimeout  | Devuelve el timeout utilizado|
| settimeout <timeout> | Cambia el timeout utilizado|
| geterror  | Devuelve el file hacia donde se redirige el error|
| seterror <errfile>  | Cambia el file hacia donde se redirige el error| 
| getfilter  | Devuelve el filtro que usa el transform|
| setfilter <filter> | Cambia el filtro que usa el transform|
| filter?  | ComandoAdvierte si el filtro esta encendido o no|
| enablefilter   | Enciende el filtro|  
| disablefilter   | Apaga el filtro|  
