# 確保 CNI 目錄存在
sudo mkdir -p /opt/cni/bin
sudo mkdir -p /etc/cni/net.d

# 複製 CNI 執行檔並賦予執行權限
sudo cp cni/ebpfcni /opt/cni/bin/

# 複製 CNI 設定檔，複製過去後 Node 會變 Ready
sudo cp cni/10-ebpfcni.conf /etc/cni/net.d/

# 建立一個簡單的 Pod 來測試 CNI
kubectl run nginx --image=nginx

# 建立一個 netshoot 去發出請求看看
kubectl run netshoot --image=nicolaka/netshoot -- sleep 3600

# 發出請求
kubectl exec netshoot -- curl -s $(kubectl get pod nginx -o jsonpath='{.status.podIP}')

# 清理
kubectl delete pod nginx
kubectl delete pod netshoot
