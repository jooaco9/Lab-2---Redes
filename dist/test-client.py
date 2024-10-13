from jsonrpc_redes import connect

def test_client():
    # Este es el cliente de prueba que se ejecuta contra el
    # servidor de prueba en el módulo server.

    print('=============================')
    print('Iniciando pruebas de casos sin errores.')

    connS1 = connect('200.0.0.10', 8080)
    value = 'Testing!'
    result = connS1.echo(value)
    assert result == value
    print('Test simple completado.')
    
    result = connS1.echo(message='No response!', notify=True)
    assert result == None
    print('Test de notificación completado.')

    result = connS1.echo_concat('a', 'b', 'c', 'd')
    assert result == 'abcd'
    print('Test de múltiples parámetros completado')

    result = connS1.echo_concat(msg1='a', msg2='b', msg3='c', msg4='d')
    assert result == 'abcd'
    print('Test de múltiples parámetros con nombres completado')
    
    result = connS1.echo(message=5)
    assert result == 5
    print('Otro test simple completado.')
    
    result = connS1.sum(1, 2, 3, 4, 5)
    assert result == 15
    print('Test de suma completado.')

    result = connS1.sum(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    assert result == 55
    print('Segundo test de suma con 10 parámetros completado')

    print('=============================')
    print('Pruebas de casos sin errores completadas.')
    print('=============================')
    print('Iniciando pruebas de casos con errores.')

    connS2 = connect('200.100.0.15', 8080)
    
    try:
        connS2.echo()
    except Exception as e:
        print('Llamada incorrecta sin parámetros. Genera excepción necesaria.')
        print(e.code, e.message)
    else:
        print('ERROR: No lanzó excepción.')
        
    try:
        connS2.foobar(5, 6)
    except Exception as e:
        print('Llamada a método inexistente. Genera excepción necesaria.')
        print(e.code, e.message)
    else:
        print('ERROR: No lanzó excepción.')

    try:
        connS2.echo_concat('a', 'b', 'c')
    except Exception as e:
        print('Llamada incorrecta genera excepción interna del servidor.')
        print(e.code, e.message)
    else:
        print('ERROR: No lanzó excepción.')

    try:
        connS2.echo_concat('a', msg2='b', msg3='c', msg4='d')
    except Exception as e:
        print('Llamada incorrecta genera excepción en el cliente.')
        print(e)
    else:
        print('ERROR: No lanzó excepción.')
    
    print('=============================')
    print("Pruebas de casos con errores completadas.")
    
if __name__ == "__main__":
    test_client()