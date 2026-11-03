# Using the official UNSW-NB15 training / testing sets

1. Download `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from the
   UNSW Canberra Cyber site (search "UNSW-NB15 dataset" – "Training and testing sets" folder).
2. Put them in `data/unsw/` (git-ignored).
3. Run:

```bash
python main.py batch --train data/unsw/UNSW_NB15_training-set.csv \
                     --input data/unsw/UNSW_NB15_testing-set.csv \
                     --model models/unsw.joblib --db output/unsw.db
python main.py dashboard      # choose unsw.db in the sidebar
```
