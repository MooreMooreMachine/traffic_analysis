import pandas as pd  
from pathlib import Path  


df1 = pd.read_csv(Path('C:ПУТЬ ДО РАНЕЕ ПОЛУЧЕННОГО CSV'))  
result_df_2 = df1.groupby(['signature', 'src_ip']).agg(DstIP=('dest_ip', lambda x: '\n'.join(set(x))), Count=('src_ip', 'count'), Files=('filename', lambda x: '\n'.join(set(x)))).reset_index()  result_df_2.to_csv(Path('ПУТЬ ДО ИТОГОВОГО CSV'))
