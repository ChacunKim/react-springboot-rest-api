import React from "react";

/*
    구조
    App
     ㄴ ProductList
       - Product
       - Product
       - product
    Summary
    Summary에 item을 추가하려면 App에서 summary로 전달해야되는데,
    Product는 ProductList의 자식, ProductList는 App의 자식이다.
    js에서는 자식이 부모에게 함수를 전달하지 못한다. 따라서 부모에 함수를 만들어서 자식(ProductList -> Product)으로 전달해야 한다.
*/

export function Product(props) {
    const productId = props.productId;
    const productName = props.productName;
    const category = props.category;
    const price = props.price;
    const handleAddBtnClicked = e =>{
        // console.log(productId, "clicked!")

        props.onAddClick(productId);
    };

    return <>
        <div className="col-2">
            <img className="img-fluid" src="https://i.imgur.com/HKOFQYa.jpeg" alt=""/>
        </div>
        <div className="col">
            <div className="row text-muted">{category}</div>
            <div className="row">{productName}</div>
        </div>
        <div className="col text-center price">{price}원</div>
        <div className="col text-end action">
            <button onClick={handleAddBtnClicked} className="btn btn-small btn-outline-dark" href="">추가</button>
        </div>
    </>
}