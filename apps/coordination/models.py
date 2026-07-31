from django.db import models


class CoordDelta(models.Model):
    """
    An encrypted, signed CRDT delta for coordination data (architecture §13):
    safe/danger zones, shelters, hospitals, resource + rescue + missing-person
    requests, volunteer coordination.

    The server redistributes deltas by a COARSE geohash topic (precision ~5 =
    ~5km) that the CLIENT chooses to attach. The server cannot read the delta;
    it only fans out ciphertext to others subscribed to the same shard. The
    geohash is the one deliberate metadata leak (a city-district), documented
    as a trade-off in §5/§13.
    """
    delta_id = models.CharField(max_length=64, primary_key=True)  # hex content id
    geohash = models.CharField(max_length=12, db_index=True)      # coarse shard
    ciphertext = models.BinaryField()   # signed + group-encrypted CRDT delta
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [models.Index(fields=["geohash", "created_at"])]
