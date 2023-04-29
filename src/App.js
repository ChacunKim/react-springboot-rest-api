import './App.css'
import 'bootstrap/dist/css/bootstrap.css'
import React, {useEffect, useState} from "react";
import {ProductList} from "./components/ProductList";
import {Summary} from "./components/Summary";
import axios from "axios";


function App() {
    const [products, setProducts] =useState([
        {productId: 'uuid-1', productName: '콜롬비아 커피1', category: '커피빈', price: 5000},
        {productId: 'uuid-2', productName: '콜롬비아 커피2', category: '커피빈', price: 5000},
        {productId: 'uuid-3', productName: '콜롬비아 커피3', category: '커피빈', price: 5000}
    ]);

    const [items, setItems] = useState([])

    const handleAddClicked = productId =>{
        const product = products.find(v => v.productId === productId);
        const found = items.find(v => v.productId === productId);

        //map: 루프를 돌며 새로운 배열이 만들어짐. id와 같은 요소: 새로운 객체 반환
        // 장바구니 안에서 같은 id를 찾았을 경우: ...v: v 객체 복사, count 라는 속성 추가, +1 ::::해당 product 의 count +1 증가
        // 장바구니 안에서 같은 id를 못 찾았을 경우: v 객체 그대로 리턴, items(장바구니)에 product 새로 담음. :::: 장바구니에 new product 담김.
        const updatedItems =
            found ? items.map(v => (v.productId === productId) ? {...v, count: v.count + 1} : v) : [...items, {...product, count: 1}]
        setItems(updatedItems);

        //products: 위의 const에서 정의한 `상태`로부터 정보를 가져옴.
      console.log(products.find(v => v.productId === productId), "added!")
    };


    //useEffect: 필요한 정보가 로드된 후 이벤트 실행. 랜더링이 끝난 후 실행
    //두 번째 인자(deps)로 빈 배열[]을 주면 한 번만 실행된다.
    //랜더링이 끝난 후 한 번 실행.
    //axios: 비동기 작업. 서버-데이터 업데이트. 비동기 작업은 모두 useEffect 안에서 작업.
    useEffect(() => {
        axios.get('http://localhost:8080/api/v1/products')
            .then(v => setProducts(v.data)) //서버에서 상품목록을 가져온 후 UI setting
    }, []);

    const handleOrderSubmit = (order) =>{
        if (items.length == 0){
            alert("아이템을 추가해 주세요");
        }else{
            axios.post("http://localhost:8080/api/v1/orders", {
                email : order.email,
                address: order.address,
                postcode: order.postcode,
                orderItems: items.map( v => ({
                        productId: v.productId,
                        category: v.category,
                        price: v.price,
                        quantity: v.count
                    }))
            }).then(v => alert("주문이 정상적으로 접수되었습니다."), e => {
                alert("서버 장애");
                console.error(e)
            })
        }
    }

  return (
      <div className="container-fluid">
      <div className="row justify-content-center m-4">
        <h1 className="text-center">Grids & Circle</h1>
      </div>
      <div className="card">
        <div className="row">
          <div className="col-md-8 mt-4 d-flex flex-column align-items-start p-3 pt-0">
            <ProductList products={products} onAddClick={handleAddClicked}/>
          </div>
          <div className="col-md-4 summary p-4">
            <Summary items={items} onOrderSubmit={handleOrderSubmit}/>
          </div>
        </div>
      </div>
      </div>
  );
}

export default App;
