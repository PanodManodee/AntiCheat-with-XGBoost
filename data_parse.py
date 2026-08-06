from pathlib import Path
import multiprocessing as mp

import pandas as pd

from ParserProtobufLogs.parser_utils import RingBufferParser

dataset = Path(".")
bin_files = list(dataset.rglob("Server/*.bin"))


def parse(file):
    parser = RingBufferParser.from_file(file)
    df = parser.to_dataframe()
    df["session"] = file.parents[2].name
    df["match"] = file.parents[1].name
    df["file"] = file.name
    # for col in df.columns:
    #    non_null = df[col].dropna()
    #    if len(non_null) and isinstance((non_null.iloc[0]), dict):
    #        expanded = pd.json_normalize(df[col]).add_prefix(f"{col}.")
    #        df = pd.concat([df.drop(columns=[col]), expanded], axis=1)
    dict_cols = []
    for col in df.columns:
        non_null = df[col].dropna()
        if len(non_null) and isinstance(non_null.iloc[0], dict):
            dict_cols.append(col)
    for col in dict_cols:
        expanded = pd.json_normalize(df[col])
        expanded.columns = [f"{col}.{c}" for c in expanded.columns]
        df = pd.concat([df.drop(columns=[col]), expanded], axis=1)
    return df


if __name__ == "__main__":
    files = list(Path("./dataset").rglob("Server/*.bin"))
    print(f"Found {len(files)} .bin files")
    with mp.Pool(processes=4) as pool:
        results = pool.map(parse, files)
    df_all = pd.concat(results, ignore_index=True)
    print(df_all.info())
    df_all.to_csv("parsed_all_packets.csv", index=False)
