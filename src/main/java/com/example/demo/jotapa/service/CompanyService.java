package com.example.demo.jotapa.service;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.ReflectionUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.ReflectionUtils.FieldFilter;

//import com.amazonaws.util.AWSRequestMetrics.Field;
import com.example.demo.jotapa.model.entity.CompanyEntity;
import com.example.demo.jotapa.model.repository.CompanyRepository;

@Service
public class CompanyService {
	@Autowired
	private CompanyRepository repository;
	
	public CompanyEntity saveCompany(CompanyEntity company) {
		return repository.save(company);
	}
	
	public List<CompanyEntity> saveCompanies(List<CompanyEntity> companies){
		return repository.saveAll(companies);
	}
	
	public CompanyEntity getCompany(int id) {
		return repository.findById(id).orElse(null);
	}
	
	//public CompanyEntity getByName(String name) {
	//	return repository.findByName();
	//s}
	
	public List<CompanyEntity> getCompanies(){
		return repository.findAll();
	}
	
	public String deleteById(int id) {
		repository.deleteById(id);
		return "It's been succesfully deleted";
	}
	
	public CompanyEntity updateCompany(CompanyEntity company) {
		CompanyEntity existingCompany = repository.findById(company.getId()).orElse(null);
		existingCompany.setCity(company.getCity());
		existingCompany.setCountry(company.getCountry());
		existingCompany.setState(company.getState());
		existingCompany.setZip(company.getZip());
		return repository.save(existingCompany);
	}

	public CompanyEntity updateProductByFields(int id, Map<String, Object> fields) {
		CompanyEntity existingCompany = repository.findById(id).get();
		
		fields.forEach((key,value)->{
			Field field = ReflectionUtils.findRequiredField(CompanyEntity.class, key);
			field.setAccessible(true);
			ReflectionUtils.setField(field, existingCompany, value);
		});
		
		return repository.save(existingCompany);
	}
}
