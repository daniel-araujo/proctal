import itertools

def all_combinations(iterable, length=None):
    """Similar to the combinations function in itertools but includes
    combinations up to and including the length.
    """
    if length == None:
        length = len(iterable)

    return itertools.chain(*map(lambda x: itertools.combinations(iterable, x), range(1, length + 1)))
