Последовательность действий:
1. Обновляем БД suricata: *sudo suricata-update*
2. Запускаем offline анализ файлов трафика: *sudo suricata -r /path/to/traffic/folder -l /path/to/logs/location -v*
3. Записываем в файл заголовок таблицы *echo 'timestamp,src_ip,dest_ip,signature' > ./timestamps_filenames.csv*
4. Парсинг результатов работы suricata - файла eve.json: *cat ./eve.json | jq -r 'select(.alert.severity == 1) | "\(.timestamp),\(.src_ip),\(.dest_ip),\(.alert.signature)"' >> ./timestamps_filenames.csv*
5. Запуск скрипта по заполнению файла *script_fill.py*
6. Запуск скрипта по группировке *pandas_group.py*
