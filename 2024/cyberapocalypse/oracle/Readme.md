# Writeup de Oracle - HTB Cyberapolacypse 2024
<br><br>

## Índice

- Introducción y descripción del desafío
  - tl;dr
- Análisis Estático
- Estrategia de explotación
<br><br>

## Introducción y descripción del desafío
Este desafío de la categoría de pwn llamado Oracle spwanea un contenedor de Docker
y nos permite descargar el binario, el código fuente y el entorno para su ejecución,
además nos proporciona la siguiente descripción:
<br><br>

> Traversing through the desert, you come across an Oracle. One of five in the entire arena, an oracle gives you the power to watch over the other competitors and send infinitely customizable plagues upon them. Deeming their powers to be too strong, the sadistic overlords that run the contest decided long ago that every oracle can backfire - and, if it does, you will wish a thousand times over that you had never been born. Willing to do whatever it takes, you break it open, risking eternal damnation for a chance to turn the tides in your favour.

<br><br>
Según la descripción del desafío soy un competidor que atraviesa el desierto y se encuentra un Oráculo
el cual me concede el poder de vigilar a otros competidores y enviarles plagas infinitamente, debido a
que estos poderes son muy fuertes, los "señores sádicos" quienes dirigen la competición deciden que
todo Oráculo puede romperse y si esto sucede lo voy a lamentar.

Como soy un pillo sin temor a la condena eterna decido romperlo y cambiar el rumbo de la competición
a mi favor.
<br><br>

## tl;dr

- Crea una conexión y llama a *handle_plague()* para liberar *plague_content*
- Crea otra conexión y llama a *handle_plague()* para leakear *LIBC* de *plague_content*
- Crea otra conexión y desborda un buffer en el stack de *parse_headers* para controlar el flujo
de ejecución
- Hace *ROP* para redirigir el socket de la conexión para *STDIN* y *STDOUT*
- Obtiene RCE
<br><br>

## Análisis Estático

Gracias a que el desafío nos da el código fuente puedo comenzar a analizar el código y buscar algunos
bugs partiendo de la función *main*, esta función simplemente crea un socket para aceptar 5 conexiones
(los cinco competidores) mediante el puerto *9001* y llama a la función *handle_request*
para procesar las conexiones.

Con el objetivo de romper el Oráculo es probable que en la función *handle_request* sea donde inicie la 
fiesta, entonces echemosle un vistazo:

```C
void handle_request() {
    // take in the start-line of the request
    // contains the action, the target competitor and the oracle version
    char start_line[MAX_START_LINE_SIZE];

    char byteRead;
    ssize_t i = 0;

    for (ssize_t i = 0; i < MAX_START_LINE_SIZE; i++) {
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        if (start_line[i-1] == '\r' && byteRead == '\n') {
            start_line[i-1] == '\0';
            break;
        }

        start_line[i] = byteRead;
    }

    sscanf(start_line, "%7s %31s %15s", action, target_competitor, version);
    parse_headers();

    // handle the specific action desired
    if (!strcmp(action, VIEW)) {
        handle_view();
    } else if (!strcmp(action, PLAGUE)) {
        handle_plague();
    } else {
        perror("ERROR: Undefined action!");
        write(client_socket, BAD_REQUEST, strlen(BAD_REQUEST));
    }

    // clear all request-specific values for next request
    memset(action, 0, 8);
    memset(target_competitor, 0, 32);
    memset(version, 0, 16);
    memset(headers, 0, sizeof(headers));
}
```

Esta función inicialmente recibe 1024 bytes (MAX_START_LINE_SIZE) y los almacena en el buffer *start_line*, algo a 
notar es la implementación de esta recepción que es realizada byte a byte por el socket y si el byte actual que está
recibiendo es igual a *b'\r'* y el byte anterior a *b'\n'* detiene la recepción.

Pero hay un inconveniente en esta implementación: 

```C
// [ ... ]

        if (start_line[i-1] == '\r' && byteRead == '\n') {
            start_line[i-1] == '\0'; // Bug
            break;
        }

// [ ... ]
```

- Si se valida b'\r\n', la instrucción *start_line[i-1] == '\0';* no va a delimitar el buffer con NULL ya que no lo está
asignando sino comparando

Luego del buffer setea 3 variables globales *action, target_competitor, version*, llama a la función *parse_headers* y
dependiendo la acción (el poder a utilizar) llama a *handle_view* y *handle_plague*.

Hasta ahora todo bien, con este bug no podré ganarme la ira de los "señores sádicos", veamos *parse_header*:

```C
void parse_headers() {
    // first input all of the header fields
    ssize_t i = 0;
    char byteRead;
    char header_buffer[MAX_HEADER_DATA_SIZE];

    while (1) {                                                         // ## [ 1 ]
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        // clean up the headers by removing extraneous newlines
        if (!(byteRead == '\n' && header_buffer[i-1] != '\r'))     
            header_buffer[i] = byteRead;                        	// ## [ 2 ]

        if (!strncmp(&header_buffer[i-3], "\r\n\r\n", 4)) {
            header_buffer[i-4] == '\0';                        		// ## [ 3 ]
            break;
        }

        i++;
    }

    // now parse the headers
    const char *delim = "\r\n";
    char *line = strtok(header_buffer, delim);

    ssize_t num_headers = 0;

    while (line != NULL && num_headers < MAX_HEADERS) {
        char *colon = strchr(line, ':');

        if (colon != NULL) {
            *colon = '\0';

            strncpy(headers[num_headers].key, line, MAX_HEADER_LENGTH);
            strncpy(headers[num_headers].value, colon+2, MAX_HEADER_LENGTH);        // colon+2 to remove whitespace
            
            num_headers++;
        }

        line = strtok(NULL, delim);
    }
}
```

En esta función se reciben bytes para parsear los headers pero sucede algo similar a *handle_request* en la 
implementación que podría romper el Oráculo.

En `[ 1 ]`, como se observa en el código, se crea un bucle infinito para la recepción de los headers. Esto es un error
porque no se limita el número de bytes a leer como en *handle_request*

Luego en `[ 2 ]` se almacenan los bytes en el buffer `header_buffer[MAX_HEADER_DATA_SIZE]`, esto indica que es posible
enviar más bytes de la capacidad del buffer (1024 bytes) hasta que decida detener la recepción en `[ 3 ]`
permitiendo abusar del Stack Buffer Overflow.

En `[ 3 ]` sucede lo mismo que en *handle_request*, no se delimita el buffer con NULL.

Una vez se parseen los headers el Oráculo me concede el poder de, ya sea, vigilar a otros competidores (*handle_view*)
o enviarles plagas (*handle_plague*), vigilar a los otros competidores no tiene nada interesante como poder enviarles
plagas, porque el Oráculo me permite enviar la plaga que yo quiera, con razón los "señores sádicos" los nerfearon.

Analicemos este poder:

```C
void handle_plague() {
    if(!get_header("Content-Length")) {
        write(client_socket, CONTENT_LENGTH_NEEDED, strlen(CONTENT_LENGTH_NEEDED));
        return;
    }

    // take in the data
    char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
    char *plague_target = (char *)0x0;

    if (get_header("Plague-Target")) {
        plague_target = (char *)malloc(0x40);
        strncpy(plague_target, get_header("Plague-Target"), 0x1f);
    } else {
        write(client_socket, RANDOMISING_TARGET, strlen(RANDOMISING_TARGET));
    }

    long len = strtoul(get_header("Content-Length"), NULL, 10);                

    if (len >= MAX_PLAGUE_CONTENT_SIZE) {                                      // ## [ 1 ]
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);                               // ## [ 2 ]

    if(!strcmp(target_competitor, "me")) {
        write(client_socket, PLAGUING_YOURSELF, strlen(PLAGUING_YOURSELF));
    } else if (!is_competitor(target_competitor)) {
        write(client_socket, PLAGUING_OVERLORD, strlen(PLAGUING_OVERLORD));
    } else { 
        dprintf(client_socket, NO_COMPETITOR, target_competitor);

        if (len) {
            write(client_socket, plague_content, len);                         // ## [ 3 ]
            write(client_socket, "\n", 1);
        }
    }

    free(plague_content);                                                      // ## [ 4 ]


    if (plague_target) {
        free(plague_target);                                                   // ## [ 5 ]
    }
}
```

Con esta función pasan cosas interesantes y me doy cuenta que no solo con romper el Oráculo me arriesgo a la
condena eterna.

Inicialmente asigna 2048 bytes (MAX_PLAGUE_CONTENT_SIZE) para *plague_content*, luego si se específica
el header *Plague-Target* le podré enviar la plaga a un competidor en específico o sino será a alguno aleatorio.

Independientemente de la opción que elija, el Oráculo va a obtener obligatoriamente el header *Content-Length* para
la longitud de los bytes a recibir en *plague_content*, pero en caso que este sea mayor o igual a
*MAX_PLAGUE_CONTENT_SIZE* entonces lo hace igual a *MAX_PLAGUE_CONTENT_SIZE - 1*

```C
// [ ... ]

    long len = strtoul(get_header("Content-Length"), NULL, 10);                

    if (len >= MAX_PLAGUE_CONTENT_SIZE) {                                      // ## [ 1 ]
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);                               // ## [ 2 ]

// [ ... ]
```

Esto presenta un bug en `[ 1 ]` que triggea un Integer Overflow debido al tipo de dato de la variable *len* (`long`)
si el retorno de *strtoul* es un `unsigned long` que no puede ser representado por `signed long (long)`, permitiendo
así recibir más bytes de MAX_PLAGUE_CONTENT_SIZE causando un Heap Overflow en `[ 2 ]`

Luego verifica que no intente enviarme la plaga a mi mismo o a los "señores", porque en caso que les envie plaga a
ellos quedo condenado por siempre, y por último libera los punteros asignados (*plague_content* y *plague_target*)

Entonces según mi análisis pude identificar 2 bugs que podrían ser utiles para romper el Oráculo:

- Stack Buffer Overflow en *parse_headers()*
- Heap Overflow en *handle_plague()*

Ahora veamos que protecciones tiene el Oráculo y como podría aprovecharlas con estos bugs.
<br><br>

## Estrategia de explotación

Para ver como exploto este Oráculo primero debo saber que protecciones tiene el ejecutable:

```
$ checksec ./oracle
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Como se observa, gracias a *checksec* me doy cuenta que el binario no tiene canary, esto es interesante porque
con el Stack Buffer Overflow en *parse_headers* podria sobreescribir el retorno sin preocuparme por la verificación
de la cookie, pero el ejecutable tiene PIE (Position Independent Executable) entonces sólo tendría las direcciones
relativas a las instrucciones y no es suficiente.

Por tanto para poder tener control del flujo de ejecución voy a necesitar un leak de una direccón absoluta, además
como el binario también tiene NX/DEP (Data Execution Protection) es necesario hacer *Return Oriented Programming*

Veamos como puedo obtener ese leak, en la función *handle_plague* además del Heap Overflow hay un descuido al liberar
la memoria dinámica y es que no se está limpiando el puntero a esa memoria después de liberarla en `[ 4 ]` y `[ 5 ]`

```C
// [ ... ]

    free(plague_content);                                                      // ## [ 4 ]


    if (plague_target) {
        free(plague_target);                                                   // ## [ 5 ]
    }
```

Este tipo de fallos generalmente producen vulnerabilidades de Use-After-Free, en este caso no aprovecho este
error para corromper la memoria sino para leakear un puntero gracias al funcionamiento interno del alocador de memoria
de GLIBC, miremos como funciona esto:

- Al liberar un bloque (chunk) de memoria con la función `free`, este bloque vuelve al alocador de memoria para
su reutilización, esto lo hace internamente la función
[`_int_free`](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L4154)
- *_int_free* después de liberar un chunk examina si los bloques adyacentes también están libres,
si es así GLIBC puede combinar estos bloques adyacentes en uno más grande, este proceso se conoce como *"consolidación"*
- Si el bloque que se libera es contiguo al `top arena` (la parte superior del heap) y no hay bloques de
memoria adyacentes que se puedan combinar con él, GLIBC opta por extender el tamaño del "top arena" para incluir
el bloque recién liberado

```C
// [ ... ]

      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

// [ ... ]
```

> Nota: debo aclarar que el bloque consolidado no es fastbin sino sería la función [`malloc_consolidate`](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L4440) la encargada
de ese proceso
<br>

- En caso que no tenga que consolidar porque hay un bloque adyacente en uso, el alocador va a colocar este bloque en 
un respectivo bin basado en el tamaño del bloque, para entenderlo aún más recomiendo leer sobre el funcionamiento
interno del alocador [*malloc*](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

Bueno entendieno el funcionamiento del alocador yo sé que el bloque *plague_content* es un *small chunk* y al liberarlo
caerá primeramente en el *unsorted bin*, esto permite a GLIBC reutilizar el bloque en caso de solicitar una cantidad
de memoria igual o de menos bytes que el bloque.

Para mantener trazabilidad de los bloques libres existe una lista doblemente enlazada que utiliza dos punteros (`fd` 
y `bk`) para realizar operaciones de gestión de memoria, como la asignación y la liberación eficientes de los bloques.

```
fd: es un puntero que apunta al siguiente bloque libre en la lista enlazada
bk: es un puntero que apunta al bloque libre anterior en la lista enlazada. 
```
Entonces sabiendo eso mi idea es usar este funcionamiento para leakear una dirección absoluta de `GLibc`, para eso
hago lo siguiente:

- Seteo el header *Plague-Target* para evitar la consolidación con el "top arena"
- Libero el bloque (*plague_content*) con *handle_plague*

Entonces el bloque libre va a tener los punteros fd y bk en los primeros 16 bytes del tamaño usable del bloque

- Luego mediante otra conexión solicito el mismo bloque y sobreescribo fd para leer el puntero bk en `[ 3 ]`

```
Allocated chunk | PREV_INUSE
Addr: 0x5555555596a0                               <------ plague_content
Size: 0x811

Allocated chunk | PREV_INUSE
Addr: 0x555555559eb0                               <------ plague_target
Size: 0x51

Top chunk | PREV_INUSE
Addr: 0x555555559f00
Size: 0x20101

pwndbg> x/30gx 0x5555555596a0
0x5555555596a0: 0x0000000000000000      0x0000000000000811
0x5555555596b0: 0x0a41414141410a0d      0x00007ffff7fbabe0
0x5555555596c0: 0x0000000000000000      0x0000000000000000
0x5555555596d0: 0x0000000000000000      0x0000000000000000
0x5555555596e0: 0x0000000000000000      0x0000000000000000
0x5555555596f0: 0x0000000000000000      0x0000000000000000
0x555555559700: 0x0000000000000000      0x0000000000000000
0x555555559710: 0x0000000000000000      0x0000000000000000
0x555555559720: 0x0000000000000000      0x0000000000000000
0x555555559730: 0x0000000000000000      0x0000000000000000
0x555555559740: 0x0000000000000000      0x0000000000000000
0x555555559750: 0x0000000000000000      0x0000000000000000
0x555555559760: 0x0000000000000000      0x0000000000000000
0x555555559770: 0x0000000000000000      0x0000000000000000
0x555555559780: 0x0000000000000000      0x0000000000000000
pwndbg>
```

Teniendo un leak de libc puedo abusar del Stack Buffer Overflow, utilizarlo para bypassear el ASLR (PIE) y
conseguir gadgets que me permitan bypassear el NX.

Ya en este punto es simplemente ROPear para llamar a `execve("/bin/sh", 0, 0)`

> Algo importante a mencionar es que llamar a *execve* simplemente no basta ya que el ejecutable está en un servidor
alojado en algún lado del mundo y la shell se ejecutaría en quién sabe donde y no podría interactuar con ella

Para resolver este problema lo que hice fue redireccionar la salida y entrada estandar (STDIN y STDOUT) 
del servidor para la conexión del socket con la syscall [dup2](https://www.man7.org/linux/man-pages/man2/dup.2.html)

Y así, rompí el Oráculo y cambié el rumbo a mi favor.
<br><br>

## Conclusión

Este desafío puede tener otros enfoques de explotación como usar el heap overflow para corromper el heap y conseguir
una primitiva de lectura y escritura (r/w), también se puede ROPear para enviar la flag reutilizando el socket como

- open(flag) -> read(flag) -> write(client_socket, flag, n)

En general fue un reto entretenido con un concepto que me gustó, este fue mi [exploit](https://github.com/uns0rted/ctfs/blob/main/2024/cyberapocalypse/oracle/exploit.py)
