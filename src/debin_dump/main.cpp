#include <iostream>
#include <string>
#include <set>

#include <boost/range/adaptor/map.hpp>

#include <nc/config.h>

#include <nc/common/Foreach.h>

#include <nc/core/Context.h>
#include <nc/core/Driver.h>
#include <nc/core/image/Image.h>
#include <nc/core/image/Section.h>
#include <nc/core/arch/Instruction.h>
#include <nc/core/ir/MemoryLocation.h>
#include <nc/core/ir/BasicBlock.h>
#include <nc/core/ir/Terms.h>
#include <nc/core/ir/Term.h>
#include <nc/core/ir/Jump.h>
#include <nc/core/ir/Function.h>
#include <nc/core/ir/Functions.h>
#include <nc/core/ir/Statement.h>
#include <nc/core/ir/dflow/Dataflows.h>
#include <nc/core/ir/vars/Variables.h>
#include <nc/core/ir/vars/Variable.h>
#include <nc/core/ir/types/Types.h>
#include <nc/core/ir/types/Type.h>
#include <nc/core/ir/calling/Signatures.h>
#include <nc/core/ir/calling/FunctionSignature.h>
#include <nc/core/ir/calling/Hooks.h>
#include <nc/core/ir/calling/EntryHook.h>
#include <nc/arch/x86/X86Registers.h>

#include "json.hpp"

using json = nlohmann::json;



//json term_json(const Term* term, json* j_terms, const nc::core::ir::types::Types* types) {
//  switch (term->kind()) {
//    case MEMORY_LOCATION_ACCESS:
//    const auto* instruction = term->statement()->instruction();
//      if (instruction != NULL &&
//          //location == variable.memoryLocation() &&
//          location.domain() >= nc::core::ir::MemoryDomain::FIRST_REGISTER &&
//          location.domain() <= nc::core::ir::MemoryDomain::LAST_REGISTER) {
//        auto* type = types->getType(term);
//        json j_term;
//        j_term["pc"] = instruction->addr();
//        j_term["kind"] = term->kind();
//        j_term["base_register"] = location.domain() - nc::core::ir::MemoryDomain::FIRST_REGISTER;
//        j_term["offset"] = location.addr();
//        j_term["size"] = location.size();
//        j_term["is_integer"] = type->isInteger();
//        j_term["is_pointer"] = type->isPointer();
//        j_term["isSigned"] = type->isSigned();
//        j_term["isUnsigned"] = type->isUnsigned();
//        j_terms.push_back(j_term);
//      }
//    case DEREFERENCE:
//    case UNARY_OPERATOR:
//    case BINARY_OPERATOR:
//    default:
//      break;
//  }
//}
//
//json cflow_vars_json(ByteAddr addr, const nc::core::ir::types::Types* types, nc::core::Context* context, std::set<ByteAddr>& addrs) {
//  json j_terms = json::array();
//  if (addrs.find(addr) != std::set<ByteAddr>::end()) {
//    addrs.insert(addr);
//    auto basicBlock = context->program()->getBasicBlockCovering(addr);
//    foreach(const auto& stmt, basicBlock->statements()) {
//      if (stmt->instruction()->addr() == addr) {
//        if (stmt->kind() == nc::core::ir::Statement::ASSIGNMENT) {
//
//        } else if (stmt->kind() == nc::core::ir::Statement::TOUCH) {
//
//        }
//      }
//    }
//  } else {
//    return j_terms;
//  }
//}

json variable_json(const nc::core::ir::vars::Variable& variable, const nc::core::ir::types::Types* types, bool filt_flags) {
  std::set<int> pcs;
  json j_terms = json::array();
  foreach (auto& termAndLocation, variable.termsAndLocations()) {
    const auto* term = termAndLocation.term;
    const auto location = termAndLocation.location;
    const auto* instruction = term->statement()->instruction();
    if (instruction != NULL) {
      int pc = instruction->addr();
      if (location.domain() >= nc::core::ir::MemoryDomain::FIRST_REGISTER &&
          location.domain() <= nc::core::ir::MemoryDomain::LAST_REGISTER &&
          pcs.find(pc) == pcs.end() &&
          (!filt_flags || (location.domain() <= nc::core::ir::MemoryDomain::FIRST_REGISTER + 8 &&
                           location.domain() != nc::core::ir::MemoryDomain::FIRST_REGISTER + 4 &&
                           location.domain() != nc::core::ir::MemoryDomain::FIRST_REGISTER + 5))
          ) {
        pcs.insert(pc);
        auto* type = types->getType(term);
        json j_term;
        j_term["pc"] = pc;
        j_term["kind"] = term->kind();
        j_term["base_register"] = location.domain() - nc::core::ir::MemoryDomain::FIRST_REGISTER;
        j_term["offset"] = location.addr();
        j_term["size"] = location.size();
        j_term["is_integer"] = type->isInteger();
        j_term["is_pointer"] = type->isPointer();
        j_term["is_signed"] = type->isSigned();
        j_term["is_unsigned"] = type->isUnsigned();
        j_terms.push_back(j_term);
      }
    }
  }
  json j_var;
  j_var["terms"] = j_terms;

  return j_var;
}

void dump(QString filename) {
  auto context = std::make_shared<nc::core::Context>();
  nc::core::Driver::parse(*context, filename);

  foreach (auto *section, context->image()->sections()) {
    if (section->isCode()) {
      nc::core::Driver::disassemble(*context, section, section->addr(), section->endAddr());
    }
  }

  nc::core::Driver::decompile(*context);

  auto* types = context->types();
  auto* signatures = context->signatures();
  auto* hooks = context->hooks();
  auto* variables = context->variables();
  auto* functions = context->functions();

  json j_binary;

  json j_vars = json::array();
  foreach (auto& variable, variables->list()) {
    json j_var = variable_json(*variable, types, true);
    if (!j_var["terms"].empty()) {
      j_vars.push_back(j_var);
    }
  }
  j_binary["variables"] = j_vars;

  json j_ifthen_vars = json::array();
  foreach (const auto& variable, context->ifThenVariables_) {
    json j_var = variable_json(*variable, types, false);
    if (!j_var["terms"].empty()) {
      j_ifthen_vars.push_back(j_var);
    }
  }
  j_binary["ifthen_variables"] = j_ifthen_vars;

  json j_ifthenelse_vars = json::array();
  foreach (const auto& variable, context->ifThenElseVariables_) {
    json j_var = variable_json(*variable, types, false);
    if (!j_var["terms"].empty()) {
      j_ifthenelse_vars.push_back(j_var);
    }
  }
  j_binary["ifthenelse_variables"] = j_ifthenelse_vars;

  json j_switch_vars = json::array();
  foreach (const auto& variable, context->switchVariables_) {
    json j_var = variable_json(*variable, types, false);
    if (!j_var["terms"].empty()) {
      j_switch_vars.push_back(j_var);
    }
  }
  j_binary["swith_variables"] = j_switch_vars;

  json j_dowhile_vars = json::array();
  foreach (const auto& variable, context->doWhileVariables_) {
    json j_var = variable_json(*variable, types, false);
    if (!j_var["terms"].empty()) {
      j_dowhile_vars.push_back(j_var);
    }
  }
  j_binary["dowhile_variables"] = j_dowhile_vars;

  json j_while_vars = json::array();
  foreach (const auto& variable, context->whileVariables_) {
    json j_var = variable_json(*variable, types, false);
    if (!j_var["terms"].empty()) {
      j_while_vars.push_back(j_var);
    }
  }
  j_binary["while_variables"] = j_while_vars;

  std::cout << j_binary.dump(3) << std::endl;

  //foreach (const auto& function, functions->list()) {
  //  foreach (const auto& block, function->basicBlocks()) {
  //    foreach (const auto& statement, block->statements()) {
  //      if (statement->is<nc::core::ir::Jump>()) {
  //        const nc::core::ir::Jump* jump = statement->asJump();
  //        if (jump->isConditional()) {
  //          const nc::core::ir::Term* term = jump->condition();
  //          std::cout << variable_json(*(variables->getVariable(term)), types).dump(3);
  //        }
  //      }
  //    }
  //  }
  //}


  //json j_functions = json::array();
  //foreach (auto &function2signature, signatures->function2signature_) {
  //  json j_function;
  //  auto function = function2signature.first;
  //  auto signature = function2signature.second;
  //  json j_args = json::array();
  //  if (auto entryHook = hooks->getEntryHook(function)) {
  //    foreach (const auto &argument, signature->arguments()) {
  //      json j_arg;
  //      json j_terms = json::array();
  //      auto arg_term = entryHook->getArgumentTerm(argument.get());
  //      auto arg_var = variables->getVariable(arg_term);
  //      foreach (auto& termAndLocation, arg_var->termsAndLocations()) {
  //        const auto* term = termAndLocation.term;
  //        const auto location = termAndLocation.location;
  //        const auto* instruction = term->statement()->instruction();
  //        //if (//instruction != NULL &&
  //        //    location.domain() >= nc::core::ir::MemoryDomain::FIRST_REGISTER &&
  //        //    location.domain() <= nc::core::ir::MemoryDomain::LAST_REGISTER) {
  //          auto* type = types->getType(term);
  //          json j_term;
  //          //j_term["pc"] = instruction->addr();
  //          j_term["base_register"] = location.domain() - nc::core::ir::MemoryDomain::FIRST_REGISTER;
  //          j_term["offset"] = location.addr();
  //          j_term["size"] = location.size();
  //          j_term["is_integer"] = type->isInteger();
  //          j_term["is_pointer"] = type->isPointer();
  //          j_term["isSigned"] = type->isSigned();
  //          j_term["isUnsigned"] = type->isUnsigned();
  //          j_terms.push_back(j_term);
  //        //}
  //      }
  //      j_arg["terms"] = j_terms;
  //      j_args.push_back(j_arg);
  //    }
  //  }
  //  j_function["arguments"] = j_args;
  //  j_functions.push_back(j_function);
  //}
  //j_binary["functions"] = j_functions;

}


int main(int argc, char* argv[]){
  if (argc > 1) {
    dump(QString(argv[1]));
  }
  return 0;
}
