from detector import detect_suspicious

if __name__ == '__main__':
    df = detect_suspicious('logs.csv')
    print(df.columns)
    print(df.head().to_string())
