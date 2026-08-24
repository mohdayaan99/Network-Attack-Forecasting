import pandas as pd
df = pd.read_parquet('data/processed/windowed_data.parquet')
print('Shape:', df.shape)
print()
print('Future attack distribution:')
print(df['future_attack'].value_counts())
print()
print('All windows:')
for i, row in df.iterrows():
    ws = row['window_start'].strftime('%H:%M')
    we = row['window_end'].strftime('%H:%M')
    attack_now = int(row['window_attack_count'] > 0)
    print(f'{ws}-{we} | flows={row["total_flows"]:4d} | attack_now={attack_now} | attack_next={row["future_attack"]} | next_label={row["future_dominant_label"]}')