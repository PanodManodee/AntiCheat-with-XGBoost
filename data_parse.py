from pathlib import Path
import multiprocessing as mp

import numpy as np
import pandas as pd

from ParserProtobufLogs.parser_utils import RingBufferParser

# dataset = Path("D:/SIIT/Project_AntiCheat")
# bin_files = list(dataset.rglob("Client/*.bin"))


def flatten_dict_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Recursively expand columns whose values are dicts (e.g. header.ids -> header.ids.sessionid)."""
    changed = True
    while changed:
        changed = False
        dict_cols = []
        for col in df.columns:
            non_null = df[col].dropna()
            if len(non_null) and isinstance(non_null.iloc[0], dict):
                dict_cols.append(col)
        for col in dict_cols:
            expanded = pd.json_normalize(df[col])
            expanded.columns = [f"{col}.{c}" for c in expanded.columns]
            expanded.index = df.index
            df = pd.concat([df.drop(columns=[col]), expanded], axis=1)
            changed = True
    return df


def flatten_list_columns(df: pd.DataFrame) -> pd.DataFrame:
    """ackets_server.csv", index=False)
    Handle columns whose values are lists (not caught by the dict flattener).
    - Fixed-length lists of scalars across all non-null rows  -> expand into col_0, col_1, ...
    - Lists of dicts, or variable-length lists                -> reduce to summary stats
    """
    list_cols = []
    for col in df.columns:
        non_null = df[col].dropna()
        if len(non_null) and isinstance(non_null.iloc[0], (list, tuple)):
            list_cols.append(col)

    for col in list_cols:
        non_null = df[col].dropna()
        lengths = non_null.apply(len)
        elem_is_dict = non_null.apply(
            lambda x: len(x) > 0 and isinstance(x[0], dict)
        ).any()

        if elem_is_dict:
            # list of dicts (e.g. bunches: [{...}, {...}]) -> can't expand safely, keep count only
            df[f"{col}.count"] = df[col].apply(
                lambda x: len(x) if isinstance(x, list) else 0
            )
            df = df.drop(columns=[col])

        elif lengths.nunique() == 1:
            # fixed-length list of scalars, e.g. new_location = [x, y, z] every time
            n = lengths.iloc[0]
            expanded = pd.DataFrame(
                df[col]
                .apply(lambda x: x if isinstance(x, list) else [np.nan] * n)
                .tolist(),
                index=df.index,
                columns=[f"{col}.{i}" for i in range(n)],
            )
            df = pd.concat([df.drop(columns=[col]), expanded], axis=1)

        else:
            # variable-length list of scalars, e.g. visible_players = [id1, id2, ...]
            df[f"{col}.count"] = df[col].apply(
                lambda x: len(x) if isinstance(x, list) else 0
            )
            df[f"{col}.mean"] = df[col].apply(
                lambda x: np.mean(x) if isinstance(x, list) and len(x) else np.nan
            )
            df[f"{col}.min"] = df[col].apply(
                lambda x: np.min(x) if isinstance(x, list) and len(x) else np.nan
            )
            df[f"{col}.max"] = df[col].apply(
                lambda x: np.max(x) if isinstance(x, list) and len(x) else np.nan
            )
            df = df.drop(columns=[col])

    return df


def flatten_bool_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Cast columns whose non-null values are Python bools into nullable Int64 (0/1)."""
    bool_cols = []
    for col in df.columns:
        non_null = df[col].dropna()
        if len(non_null) and isinstance(non_null.iloc[0], (bool, np.bool_)):
            bool_cols.append(col)
    for col in bool_cols:
        df[col] = df[col].astype("boolean").astype("Int64")
    return df


def flatten_all(df: pd.DataFrame) -> pd.DataFrame:
    df = flatten_dict_columns(df)
    df = flatten_bool_columns(df)
    df = flatten_list_columns(df)
    # anything still object at this point is unexpected -- surface it instead of silently failing
    remaining = df.select_dtypes(include="object").columns.tolist()
    if remaining:
        print("WARNING: columns still object dtype after flattening:", remaining)
        for col in remaining:
            sample = df[col].dropna()
            print(f"  sample from {col}:", sample.iloc[0] if len(sample) else "all NaN")
    return df


def parse(file):
    parser = RingBufferParser.from_file(file)
    df = parser.to_dataframe()
    df["session"] = file.parents[2].name
    df["match"] = file.parents[1].name
    df["file"] = file.name

    df = flatten_all(df)

    return df


if __name__ == "__main__":
    files = list(Path("./dataset/").rglob("Server/*.bin"))
    print(f"Found {len(files)} .bin files")
    with mp.Pool(processes=4) as pool:
        results = pool.map(parse, files)
    df_all = pd.concat(results, ignore_index=True)

    # datetime -> unix timestamp (seconds) so XGBoost can use it as a numeric feature
    for col in df_all.select_dtypes(include="datetime64[us, UTC]").columns:
        df_all[col] = df_all[col].astype("int64") // 10**9

    # str -> category (train with xgb.XGBClassifier(enable_categorical=True, tree_method="hist"))
    for col in df_all.select_dtypes(include="str").columns:
        df_all[col] = df_all[col].astype("category")

    print(df_all.info())
    df_all.to_csv("parsed_all_packets_server.csv", index=False)
