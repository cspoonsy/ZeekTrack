tc qdisc add dev macvlan0 handle ffff: ingress
tc filter add dev macvlan0 parent ffff: matchall action mirred egress mirror dev eth0

tc qdisc add dev macvlan0 root handle 1: prio
tc filter add dev macvlan0 parent 1: matchall action mirred egress mirror dev eth0
