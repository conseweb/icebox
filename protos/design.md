# App与Device之间的通信协议
1. 两者之间通过声波进行通信
2. App不能接触Device的pin码，pin码只能由Device向用户索取，由用户在设备上输入
3. 两者之间的通信需要进行加密，通信会话建立之前，需要进行会话密钥协商，类似ECDH

## 密钥磋商过程
   
假设密钥交换双方为Alice、Bob，其有共享曲线参数（椭圆曲线E、阶N、基点G）。
   
1. Alice生成随机整数a，计算A=aG。Bob生成随机整数b，计算B=bG。
2. Alice将A传递给Bob。A的传递可以公开，即攻击者可以获取A。由于椭圆曲线的离散对数问题是难题，所以攻击者不可以通过A、G计算出a。Bob将B传递给Alice。同理，B的传递可以公开。
3. Bob收到Alice传递的A，计算Q=b*A
4. Alice收到Bob传递的B，计算Q‘=a*B
5. Alice、Bob双方即得Q=bA=b(aG)=(ba)G=(ab)G=a(bG)=aB=Q'(交换律和结合律)，即双方得到一致的密钥Q。
   

## 加密会话建立
1. Hi  


## App状态机
1. Device Confirmed
2. Negotiated 
3. Conversation Established