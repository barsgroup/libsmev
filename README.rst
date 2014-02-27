Первоначальная настройка окружения
----------------------------------

Linux
^^^^^
1. Установить OpenSSL версии не ниже 1.0.
2. Для поддержки OpenSSL ГОСТ Р 34.11-94,  необходимо внести изменения в openssl.cnf::

    openssl_conf = openssl_def

    <...оставшееся содержимое файла...>

    [openssl_def]
    engines = engine_section

    [engine_section]
    gost = gost_section    

    [gost_section]
    soft_load=1
    default_algorithms = ALL
    
Теперь можно вызвать алгоритм ГОСТ Р 34.11-94 из консоли следующим образом:
**openssl dgst -md_gost94 filename**


Windows
^^^^^^^
1. Установить Microsoft Visual C++ Redistributable: http://www.microsoft.com/downloads/details.aspx?familyid=9B2DA534-3E03-4391-8A4D-074B9F2BC1BF

2. Установить OpenSSL версии не ниже 1.0: http://slproweb.com/download/Win32OpenSSL-1_0_1c.exe

3. Для поддержки OpenSSL алгоритма шифрования ГОСТ Р 34.11-94, необходимо внести изменения в файл конфига OpenSSL (обычно в директории с OpenSSL). Почти все совпадает со значениями из секции выше, кроме секции gost_section:::

    [gost_section]
    engine_id = gost
    dynamic_path = ./gost.dll
    default_algorithms = ALL
    
Добавить в переменные окружения путь к конфигу OpenSSL::

    OPENSSL_CONF=c:\\OpenSSL-Win32\\bin\\openssl.cfg



Благодарности
-------------

Огромное спасибо за помощь в отладке:

- Юлдашеву Руслану <yuldashev@bars-open.ru>,
- Сабитову Ринату <sabitov@bars-open.ru>,
- Кальянову Дмитрию <kalyanov@bars-open.ru>,
- Кирову Илье <kirov@bars-open.ru>

Особая благодарность:

- Сингатуллину Марселю <singatullinmt@bars-open.ru>

.. image:: https://travis-ci.org/barsgroup/libsmev.png   
   :target: https://travis-ci.org/barsgroup/libsmev