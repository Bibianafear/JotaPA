package com.example.demo.jotapa.model.entity;

import java.io.Serializable;

import javax.annotation.Generated;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;



@Entity
@Table (name="employees")

public class Employee implements Serializable  {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2L;
	@Id
	@GeneratedValue(strategy= GenerationType.AUTO)
	@Column(name = "employee_id")
	private Long id;
	
	@Column
	private String firstName;
	
	@Column
	private String lastName;
	
	@Column
	private int yearsOfExp;
	
	public Employee(){
		
	}

	public Employee(Long id, String firstName, String lastName, int yearsOfExp) {
		super();
		this.id = id;
		this.firstName = firstName;
		this.lastName = lastName;
		this.yearsOfExp = yearsOfExp;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public int getYearsOfExp() {
		return yearsOfExp;
	}

	public void setYearsOfExp(int yearsOfExp) {
		this.yearsOfExp = yearsOfExp;
	}
	
	
	
}
