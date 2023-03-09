package com.example.demo.jotapa.model.entity;

import java.io.Serializable;

import javax.annotation.Generated;
import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;



@javax.persistence.Entity
@javax.persistence.Table (name = "Company table")
public class CompanyEntity implements Serializable  {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy= GenerationType.AUTO)
	@Column(name="company_id")
	private int id;
	@Column
	private String city;
	@Column
	private String state;
	@Column
	private int zip;
	@Column
	private String country;
	
	public CompanyEntity(){
		
	}

	public CompanyEntity(int id, String city, String state, int zip, String country) {
		super();
		this.id = id;
		this.city = city;
		this.state = state;
		this.zip = zip;
		this.country = country;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public int getZip() {
		return zip;
	}

	public void setZip(int zip) {
		this.zip = zip;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}
	
	

}
