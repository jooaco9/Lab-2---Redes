from jsonrpc_redes import Server
import threading
import time
import sys

def test_server():
    # Este método es un ejemplo de cómo se puede usar el servidor.
    # Se inicia un servidor en el puerto 8080 y se añaden dos métodos
    
    host, port = '', 8080
    
    def echo(message):
        return message
        
    def summation(*args):
        return sum(args)

    def echo_concat(msg1, msg2, msg3, msg4):
        return msg1 + msg2 + msg3 + msg4
        
    server = Server((host, port))
    server.add_method(echo)
    server.add_method(summation, 'sum')
    server.add_method(echo_concat)
    server_thread = threading.Thread(target=server.serve)
    server_thread.daemon = True
    server_thread.start()
    
    print ("Servidor ejecutando: %s:%s" % (host, port))
    
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        server.shutdown()
        print('Terminado.')
        sys.exit()
    
if __name__ == "__main__":
    test_server()