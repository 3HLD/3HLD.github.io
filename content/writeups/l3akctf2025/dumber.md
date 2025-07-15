+++
title = 'dumber'
tags = [
  "crypto",
  "50 points",
  "147 solves",
]
draft = true
+++

## Dumber 
Source code của bài:

```python
from Crypto.Util.number import  bytes_to_long, long_to_bytes
from sage.all import *

a,b,p = ?,?,?

pt1="L3AK{test_"
pt2="flag}"

E = EllipticCurve(Zmod(p), [a, b])
p,q=E.random_element(),E.random_element()
u=bytes_to_long(pt1.encode())*p
v=bytes_to_long(pt2.encode())*q

# I will help u <3
print(p,u,q,v)
```
Và một file output.txt

```
(103905521866731574234430443362297034336 : 116589269353056499566212456950780999584 : 1) (171660318017081135625337806416866746485 : 122407097490400018041253306369079974706 : 1) (161940138185633513360673631821653803879 : 167867902631659599239485617419980253311 : 1) (95406403280474692216804281695624776780 : 109560844064302254814641159241201048462 : 1)
```
## Phân tích

Ở bài này cho mình một đường cong Elliptic nhưng các tham số $a,b,p$ bị ẩn đi nhưng bù lại mình được biết thông tin về 4 điểm nằm trên đường cong này. Và từng này thông tin là đủ để recover lại các thông số trên. 

Giả sử ta có 3 cặp điểm $\displaystyle ( x_{1} ,y_{1}) ,( x_{2} ,y_{2})$ và $\displaystyle ( x_{3} ,y_{3})$. Từ phương trình của đường cong thì 

$$\begin{equation*}
y^{2} =x^{3} +ax+b\bmod p
\end{equation*}$$

Từ đây nếu ta lấy hiệu các cặp điểm 
$$\begin{gather*}
y_{2}^{2} -y_{1}^{2} =x_{2}^{3} -x_{1}^{3} +ax_{2} -ax_{1}\bmod p\\
\Longrightarrow y_{2}^{2} -y_{1}^{2} =a( x_{2} -x_{1}) +x_{2}^{3} -x_{1}^{3}
\end{gather*}$$
Và 
$$\begin{gather*}
y_{3}^{2} -y_{2}^{2} =a( x_{3} -x_{2}) +x_{3}^{3} -x_{2}^{3}\\
\Longrightarrow \left( y_{3}^{2} -y_{2}^{2}\right)( x_{2} -x_{1}) =a( x_{3} -x_{2})( x_{2} -x_{1}) +\left( x_{3}^{3} -x_{2}^{3}\right)( x_{2} -x_{1})\\
y_{2}^{2} -y_{1}^{2} =a( x_{2} -x_{1}) +x_{2}^{3} -x_{1}^{3}\\
\Longrightarrow \left( y_{2}^{2} -y_{1}^{2}\right)( x_{3} -x_{2}) =a( x_{3} -x_{2})( x_{2} -x_{1}) +\left( x_{2}^{3} -x_{1}^{3}\right)( x_{3} -x_{2})\\
\Longrightarrow \left( y_{2}^{2} -y_{1}^{2}\right)( x_{3} -x_{2}) -\left( y_{3}^{2} -y_{2}^{2}\right)( x_{2} -x_{1}) =\left( x_{2}^{3} -x_{1}^{3}\right)( x_{3} -x_{2}) -\left( x_{3}^{3} -x_{2}^{3}\right)( x_{2} -x_{1})\\
\Longrightarrow \left( y_{1}^{2} -y_{2}^{2} -x_{1}^{3} +x_{2}^{3}\right)( x_{2} -x_{3}) -\left( y_{2}^{2} -y_{3}^{2} -x_{2}^{3} +x_{3}^{3}\right)( x_{1} -x_{2}) \vdots p
\end{gather*}$$
Làm tương tự với bộ 3 điểm khác thì ta cũng sẽ được 1 giá trị là bội của $\displaystyle p$. Lấy ước chung 2 biểu thức này thì ta sẽ khôi phục lại được $\displaystyle p$. 


Sau khi có lại $\displaystyle p$ và hai điểm $\displaystyle ( x_{1} ,y_{1}) ,( x_{2} ,y_{2})$ thì mọi người có thể làm như sau [Recover Curve parameters](https://crypto.stackexchange.com/questions/97811/find-elliptic-curve-parameters-a-and-b-given-two-points-on-the-curve)



Cuối cùng, sau khi recover lại xong xuôi thì mình check order và phát hiện ra order của đường cong này cũng chính là modulo $\displaystyle p$. Vậy thì để giải DLP ta sẽ sử dụng Smart's Attack.

## Script:

```python
from sage.all import *
from Crypto.Util.number import *
def attack(p, x1, y1, x2, y2):
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)
points = [
    (103905521866731574234430443362297034336, 116589269353056499566212456950780999584),
    (171660318017081135625337806416866746485, 122407097490400018041253306369079974706),
    (161940138185633513360673631821653803879, 167867902631659599239485617419980253311),
    (95406403280474692216804281695624776780, 109560844064302254814641159241201048462)
]
x1,y1 = points[0][0],points[0][1]
x2,y2 = points[1][0],points[1][1]
x3,y3 = points[2][0], points[2][1]
x4,y4 = points[3][0],points[3][1]
mul_p = (pow(y1,2)-pow(y2,2)-pow(x1,3)+pow(x2,3))*(x2-x3)-(pow(y2,2)-pow(y3,2)-pow(x2,3)+pow(x3,3))*(x1-x2)
mul_q = (pow(y2,2)-pow(y3,2)-pow(x2,3)+pow(x3,3))*(x3-x4)-(pow(y3,2)-pow(y4,2)-pow(x3,3)+pow(x4,3))*(x2-x3)
p = gcd(mul_p,mul_q)
print(p)
a,b = attack(p,x1,y1,x2,y2)
print(a,b)
E = EllipticCurve(Zmod(p), [a, b])
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)
p_fake = E(x1,y1)
u = E(x2,y2)
q = E(x3,y3)
v = E(x4,y4)
k1 = SmartAttack(p_fake,u,p)
k2 = SmartAttack(q,v,p)
print(long_to_bytes(k1)+long_to_bytes(k2))
```

`L3AK{5m4rt1_1n_Th3_h00000d!!!}`